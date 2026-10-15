/*
 * liveshell_daemon.cpp - LiveShell: the payload the user loads with their ELF launcher.
 * Lists the user's clips, mounts the chosen clip's folder into the system paths ShellUI's video
 * service can read, injects liveshell_shellui.elf into SceShellUI, adds the LiveShell tile to the
 * home screen and serves its window (liveshell_web.cpp). Stays alive to re-inject after ShellUI
 * restarts. GPL-3.0; built on OnionHEN (aydencharles/onionHEN, v0.9.0-beta2).
 *
 * Files:
 *   /data/LiveShell/video/          clips (also <USB>/LiveShell/video)
 *   /data/LiveShell/config.txt      enabled=1 / video=<path>   (written by the window)
 *   /data/LiveShell/liveshell.log   this log + copies of the ShellUI log
 *   /system_tmp/liveshell/video.txt   what ShellUI should play: a path or "off"
 *   /system_tmp/liveshell/status.txt  what ShellUI is doing: playing <path> / stopped / failed <rc>
 */
#include "liveshell.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <pthread.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <signal.h>

#include "onion/log.h"
#include "onion/proc_query.h"

extern "C" {
bool      Inject_Toolbox(int pid, uint8_t* elf);
int       pt_detach(pid_t pid, int sig);
uintptr_t set_ucred_to_ptrace(void);
uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid);
int       sceKernelTerminateProcess(int pid, int* ret);
int       sceSystemServiceGetAppIdOfRunningBigApp(void);
int       sceSystemServiceGetAppTitleId(int app_id, char* title_id);
int  sceKernelSendNotificationRequest(int, void*, size_t, int);
extern uint8_t liveshell_shellui_elf_start[];
}

__asm__(".section .rodata\n"
        ".global liveshell_shellui_elf_start\n"
        ".type   liveshell_shellui_elf_start, @object\n"
        ".align  16\n"
        "liveshell_shellui_elf_start:\n"
        ".incbin \"" LIVESHELL_SHELLUI_ELF "\"\n"
        ".previous\n");

namespace liveshell {
namespace {

constexpr const char* kMountPoint     = "/system_ex/vsh_asset/wallpaper";
constexpr const char* kPathFile       = "/system_tmp/liveshell/video.txt";
constexpr const char* kStatusFile     = "/system_tmp/liveshell/status.txt";
constexpr const char* kShellUiLog     = "/system_tmp/liveshell/shellui.log";
constexpr const char* kDimFile        = "/system_tmp/liveshell/dim.txt";
constexpr const char* kBlurFile       = "/system_tmp/liveshell/blur.txt";
constexpr const char* kMenusFile      = "/system_tmp/liveshell/menus.txt";
constexpr const char* kLooksFile      = "/system_tmp/liveshell/looks.txt";
constexpr const char* kParallaxFile   = "/system_tmp/liveshell/parallax.txt";
constexpr const char* kLogFile        = "/data/LiveShell/liveshell.log";
constexpr const char* kConfigFile     = "/data/LiveShell/config.txt";
constexpr const char* kOurMarker      = "/system_tmp/liveshell/injected";
constexpr const char* kOnionToolbox   = "/system_tmp/onionhen/ready/toolbox";
constexpr int         kOnionCtrlPort  = 9048;
constexpr off_t       kLogMaxSize     = 512 * 1024;
constexpr long        kCrashWindowSec = 120;
// Runs next to OnionHEN (tested 2026-10-15): no "OnionHEN is running" refusal any more.
constexpr bool        kOnionGuard     = false;

volatile bool g_running        = true;
volatile bool g_stop_requested = false; // stop came from the user (port 9049), not from a crash
int           g_log     = -1;
std::mutex    g_log_lock;

// Control state; g_ctl guards everything below it.
std::mutex  g_ctl;
bool        g_enabled  = true;
int         g_dim      = 25;    // default on: clips are often bright
int         g_blur     = 0;     // 0 off, 1 light, 2 strong
int         g_looks[4] = {0, 0, 0, 0}; // bottom fade, top fade, vignette, haze: 0 off, 1 light, 2 strong
bool        g_shuffle  = false; // a random clip each time the payload starts (off by default)
bool        g_game_pause = true; // no video while a game runs
bool        g_menu_hide  = true;  // hide the video in Settings / system apps (default: safer)
bool        g_parallax   = false; // nudge the video when moving between home tiles
bool        g_game_running = false;
std::string g_game_title;
std::string g_current;          // real path of the chosen clip
std::string g_mounted_folder;   // folder currently mounted on kMountPoint
bool        g_injected = false; // the ShellUI module is running (it reacts to the path file)

// ---- small file helpers ----------------------------------------------------------------------

bool write_text(const char* path, const std::string& text) {
	const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		return false;
	}
	const bool ok = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
	close(fd);
	return ok;
}

std::string read_text(const char* path, size_t max = 4096) {
	const int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return {};
	}
	std::string text(max, '\0');
	const ssize_t n = read(fd, &text[0], max);
	close(fd);
	text.resize(n > 0 ? static_cast<size_t>(n) : 0);
	return text;
}

std::string first_line(const std::string& text) {
	return text.substr(0, text.find_first_of("\r\n"));
}

bool exists(const char* path) {
	struct stat st {};
	return stat(path, &st) == 0;
}

void send_notification(const char* text, bool icon) {
	// Layout of the system's notification request (0xC30 bytes).
	struct Request {
		int32_t type, req_id, priority, msg_id, target_id, user_id, unk1, unk2, app_id, error_num, unk3;
		char    use_icon_image_uri;
		char    message[1024];
		char    uri[1024];
		char    unused[1027];
	};
	static_assert(sizeof(Request) == 0xC30, "notification request layout");
	Request req {};
	req.target_id = -1;
	snprintf(req.message, sizeof(req.message), "%s", text);
	if (icon) {
		req.use_icon_image_uri = 1;
		snprintf(req.uri, sizeof(req.uri), "%s", "cxml://psnotification/tex_icon_system");
	}
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
	log("notify: %s", text);
}

// ---- OnionHEN guard + markers ----------------------------------------------------------------

bool onion_daemon_answers() {
	const int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		return false;
	}
	sockaddr_in addr = {};
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(kOnionCtrlPort);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	const bool up = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
	close(s);
	return up;
}

long read_pid_file(const char* path) {
	const std::string text = read_text(path, 31);
	return text.empty() ? -1 : strtol(text.c_str(), nullptr, 10);
}

// ---- clips + mounting ------------------------------------------------------------------------

bool is_mp4(const char* name) {
	const size_t n = strlen(name);
	return n > 4 && name[0] != '.' && strcasecmp(name + n - 4, ".mp4") == 0;
}

std::string folder_of(const std::string& path) {
	return path.substr(0, path.rfind('/'));
}

std::string name_of(const std::string& path) {
	return path.substr(path.rfind('/') + 1);
}

bool mount_window_at(const char* mount_point, const char* source) {
	mkdir(mount_point, 0777);
	(void)unmount(mount_point, MNT_FORCE);
	char fstype[] = "nullfs", fspath_key[] = "fspath", target_key[] = "target", fstype_key[] = "fstype";
	char fspath[256], target[256];
	snprintf(fspath, sizeof(fspath), "%s", mount_point);
	snprintf(target, sizeof(target), "%s", source);
	iovec iov[] = {
	    {fstype_key, sizeof(fstype_key)}, {fstype, sizeof(fstype)},
	    {fspath_key, sizeof(fspath_key)}, {fspath, strlen(fspath) + 1},
	    {target_key, sizeof(target_key)}, {target, strlen(target) + 1},
	};
	if (nmount(iov, sizeof(iov) / sizeof(iov[0]), MNT_RDONLY) != 0) {
		log("nullfs mount %s -> %s failed (errno %d)", source, mount_point, errno);
		return false;
	}
	return true;
}

// System processes each see their own sandbox view (/mnt/sandbox/<id>/...): a mount on the real
// /system_ex does not show there, so the window is opened in every sandbox too.
void mount_window_everywhere(const std::string& folder) {
	if (!mount_window_at(kMountPoint, folder.c_str())) {
		return;
	}
	int  mounted = 0, tried = 0;
	DIR* dir     = opendir("/mnt/sandbox");
	if (dir != nullptr) {
		while (dirent* e = readdir(dir)) {
			if (e->d_name[0] == '.') {
				continue;
			}
			char point[512];
			snprintf(point, sizeof(point), "/mnt/sandbox/%s/system_ex/vsh_asset/wallpaper", e->d_name);
			struct stat st {};
			if (stat(point, &st) != 0 || !S_ISDIR(st.st_mode)) {
				continue;
			}
			++tried;
			mounted += mount_window_at(point, folder.c_str()) ? 1 : 0;
		}
		closedir(dir);
	}
	g_mounted_folder = folder;
	log("%s mounted on %s (+ %d of %d sandboxes)", folder.c_str(), kMountPoint, mounted, tried);
}

void unmount_window_everywhere() {
	int  done = 0;
	DIR* dir  = opendir("/mnt/sandbox");
	if (dir != nullptr) {
		while (dirent* e = readdir(dir)) {
			if (e->d_name[0] == '.') {
				continue;
			}
			char point[512];
			snprintf(point, sizeof(point), "/mnt/sandbox/%s/system_ex/vsh_asset/wallpaper", e->d_name);
			done += unmount(point, MNT_FORCE) == 0 ? 1 : 0;
		}
		closedir(dir);
	}
	const int main_rc = unmount(kMountPoint, MNT_FORCE);
	g_mounted_folder.clear();
	log("window closed (%s, %d sandboxes)", main_rc == 0 ? "main ok" : "main not mounted", done);
}

// Like OnionHEN's shutdown: end SceShellUI so the system starts a clean one (no module, no video).
void restart_shellui() {
	const pid_t pid = onion_find_pid("SceShellUI");
	if (pid <= 1) {
		log("restart: SceShellUI not found");
		return;
	}
	constexpr uintptr_t kDecidAuthId = 0x4800000000000022ULL; // needed for sceKernelTerminateProcess
	const uintptr_t     old          = set_proc_authid(getpid(), kDecidAuthId);
	int                 ret          = 0;
	const int           rc           = sceKernelTerminateProcess(static_cast<int>(pid), &ret);
	set_proc_authid(getpid(), old);
	if (rc != 0) {
		log("restart: TerminateProcess(%d) rc %d ret %d, SIGKILL instead", static_cast<int>(pid), rc, ret);
		kill(pid, SIGKILL);
	}
	log("restart: SceShellUI %d ended, the system starts a new one", static_cast<int>(pid));
}

// ---- config ----------------------------------------------------------------------------------

std::string looks_text() {
	return std::to_string(g_looks[0]) + " " + std::to_string(g_looks[1]) + " " + std::to_string(g_looks[2]) + " " + std::to_string(g_looks[3]);
}

void write_looks() {
	write_text(kLooksFile, looks_text() + "\n");
}

void load_config() {
	const std::string text = read_text(kConfigFile);
	size_t            pos  = 0;
	while (pos < text.size()) {
		const size_t      end  = text.find('\n', pos);
		const std::string line = first_line(text.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
		if (line.rfind("enabled=", 0) == 0) {
			g_enabled = line.substr(8) != "0";
		} else if (line.rfind("video=", 0) == 0) {
			g_current = line.substr(6);
		} else if (line.rfind("dim=", 0) == 0) {
			g_dim = std::max(0, std::min(80, atoi(line.c_str() + 4)));
		} else if (line.rfind("looks=", 0) == 0) {
			sscanf(line.c_str() + 6, "%d %d %d %d", &g_looks[0], &g_looks[1], &g_looks[2], &g_looks[3]);
			for (int& v : g_looks) {
				v = std::max(0, std::min(2, v));
			}
			g_looks[0] = g_looks[1] = 0; // bottom / top fade were removed (user)
		} else if (line.rfind("blur=", 0) == 0) {
			g_blur = std::max(0, std::min(2, atoi(line.c_str() + 5)));
		} else if (line.rfind("shuffle=", 0) == 0) {
			g_shuffle = line.substr(8) != "0";
		} else if (line.rfind("parallax=", 0) == 0) {
			g_parallax = line.substr(9) != "0";
		} else if (line.rfind("menuhide=", 0) == 0) {
			g_menu_hide = line.substr(9) != "0";
		} else if (line.rfind("gamepause=", 0) == 0) {
			g_game_pause = line.substr(10) != "0";
		}
		if (end == std::string::npos) {
			break;
		}
		pos = end + 1;
	}
	log("config: enabled=%d video=%s dim=%d shuffle=%d gamepause=%d", g_enabled ? 1 : 0, g_current.c_str(), g_dim,
	    g_shuffle ? 1 : 0, g_game_pause ? 1 : 0);
	write_text(kDimFile, std::to_string(g_dim) + "\n");
	write_text(kBlurFile, std::to_string(g_blur) + "\n");
	write_text(kMenusFile, g_menu_hide ? "1\n" : "0\n");
	write_looks();
	write_text(kParallaxFile, g_parallax ? "1\n" : "0\n");
}

void save_config() {
	write_text(kConfigFile, std::string("enabled=") + (g_enabled ? "1" : "0") + "\nvideo=" + g_current + "\ndim=" + std::to_string(g_dim) + "\nblur=" + std::to_string(g_blur) + "\nlooks=" + looks_text() +
	                            "\nshuffle=" + (g_shuffle ? "1" : "0") + "\ngamepause=" + (g_game_pause ? "1" : "0") + "\nmenuhide=" + (g_menu_hide ? "1" : "0") + "\nparallax=" + (g_parallax ? "1" : "0") + "\n");
}

// ---- telling ShellUI what to play ------------------------------------------------------------

std::string shellui_status() {
	return first_line(read_text(kStatusFile, 700));
}

// Wait until ShellUI no longer holds a clip (so its folder can be unmounted safely).
bool wait_shellui_stopped(int timeout_ms) {
	for (int waited = 0; waited < timeout_ms; waited += 100) {
		const std::string st = shellui_status();
		if (st.rfind("playing", 0) != 0 && st.rfind("starting", 0) != 0 && st.rfind("stopping", 0) != 0) {
			return true;
		}
		usleep(100 * 1000);
	}
	return false;
}

// Caller holds g_ctl.
bool apply_locked(std::string& error) {
	const bool want_video = g_enabled && !(g_game_pause && g_game_running) && !g_current.empty() && exists(g_current.c_str());
	if (g_injected) {
		write_text(kPathFile, "off\n");
		if (!wait_shellui_stopped(8000)) {
			error = "The home screen did not release the old video";
			log("apply: ShellUI still busy (%s)", shellui_status().c_str());
			return false;
		}
	}
	if (!want_video) {
		write_text(kPathFile, "off\n");
		log("apply: video off");
		return true;
	}
	const std::string folder = folder_of(g_current);
	if (folder != g_mounted_folder || !g_injected) {
		mount_window_everywhere(folder); // also refreshes the sandboxes before a (re)injection
	}
	const std::string shown = std::string(kMountPoint) + "/" + name_of(g_current);
	write_text(kPathFile, shown + "\n");
	log("apply: %s (shown as %s)", g_current.c_str(), shown.c_str());
	return true;
}

// ---- injection -------------------------------------------------------------------------------

off_t file_size(const char* path) {
	struct stat st {};
	return stat(path, &st) == 0 ? st.st_size : -1;
}

// The injector stops ShellUI (ptrace), runs a stager up to a breakpoint and detaches. If that
// detach does not take, the whole ShellUI stays stopped (our module's heartbeat log freezes after
// ~2 ms) until the system kills it. Detect that and let it run again.
void unfreeze_if_stuck(pid_t pid) {
	usleep(400 * 1000);
	const off_t first = file_size(kShellUiLog);
	usleep(2600 * 1000); // the module waits 1.5 s, then logs ~4 lines/s
	const off_t second = file_size(kShellUiLog);
	if (second > first) {
		log("ShellUI is running (log %ld -> %ld bytes)", static_cast<long>(first), static_cast<long>(second));
		return;
	}
	log("ShellUI looks FROZEN after injection (log stuck at %ld bytes): detaching again + SIGCONT",
	    static_cast<long>(second));
	const uintptr_t old_authid = set_ucred_to_ptrace();
	const int       det        = pt_detach(pid, 0);
	const int       det_errno  = errno;
	const int       cont       = kill(pid, SIGCONT);
	if (old_authid != 0) {
		set_proc_authid(getpid(), old_authid);
	}
	usleep(1000 * 1000);
	const off_t third = file_size(kShellUiLog);
	log("unfreeze: detach %d (errno %d), SIGCONT %d, log now %ld bytes (%s)", det, det_errno, cont,
	    static_cast<long>(third), third > second ? "RUNNING again" : "still stuck");
}

pid_t inject_shellui() {
	const pid_t pid = onion_find_pid("SceShellUI");
	if (pid <= 0) {
		log("SceShellUI not found");
		return 0;
	}
	if (kOnionGuard && (onion_daemon_answers() || read_pid_file(kOnionToolbox) == pid)) {
		notify("LiveShell Engine can't run while OnionHEN is running.");
		return -1;
	}
	if (read_pid_file(kOurMarker) == pid) {
		log("already injected in ShellUI pid %d", static_cast<int>(pid));
		return pid;
	}
	unlink(kStatusFile);
	log("injecting into SceShellUI pid %d", static_cast<int>(pid));
	if (!Inject_Toolbox(static_cast<int>(pid), liveshell_shellui_elf_start)) {
		log("injection FAILED");
		notify("LiveShell Engine could not start (injection failed).");
		return -1;
	}
	write_text(kOurMarker, std::to_string(pid));
	log("injected into ShellUI pid %d", static_cast<int>(pid));
	unfreeze_if_stuck(pid);
	return pid;
}

void copy_shellui_log() {
	const std::string text = read_text(kShellUiLog, 64 * 1024);
	if (text.empty()) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_log_lock);
	const char* head = "--- ShellUI log ---\n";
	(void)write(g_log, head, strlen(head));
	(void)write(g_log, text.data(), text.size());
}

// ---- stop port (tools/stop_liveshell.bat) ----------------------------------------------------

void* stop_thread(void*) {
	const int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		return nullptr;
	}
	int on = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	sockaddr_in addr = {};
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(kStopPort);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(s, 1) != 0) {
		log("stop port %d unavailable (errno %d)", kStopPort, errno);
		close(s);
		return nullptr;
	}
	while (g_running) {
		const int c = accept(s, nullptr, nullptr);
		if (c >= 0) {
			const char* msg = "stopping\n";
			(void)write(c, msg, strlen(msg));
			close(c);
			g_stop_requested = true;
			g_running        = false;
			log("stop command received");
		}
	}
	close(s);
	return nullptr;
}

// After the first start: wait for the video to show, then add the tile (never in the video's way).
void* after_start_thread(void*) {
	bool want_video;
	{
		std::lock_guard<std::mutex> lock(g_ctl);
		want_video = g_enabled && !g_current.empty();
	}
	if (want_video) {
		for (int i = 0; i < 400 && shellui_status().rfind("playing", 0) != 0; ++i) {
			usleep(100 * 1000);
		}
		log("after start: ShellUI status '%s'", shellui_status().c_str());
		sleep(2);
	}
	const int rc = install_tile();
	if (rc == 1) {
		notify("LiveShell Engine was added to your home screen.");
	} else if (rc < 0) {
		notify_plain("LiveShell Engine: could not add the home screen tile (see liveshell.log).");
	}
	return nullptr;
}

void start_thread(void* (*fn)(void*)) {
	pthread_t t;
	if (pthread_create(&t, nullptr, fn, nullptr) == 0) {
		pthread_detach(t);
	}
}

} // namespace

// ---- shared API ------------------------------------------------------------------------------

void log(const char* fmt, ...) {
	if (g_log < 0) {
		return;
	}
	char line[600];
	const time_t now = time(nullptr);
	tm           t {};
	localtime_r(&now, &t);
	const int head = static_cast<int>(strftime(line, sizeof(line), "%H:%M:%S ", &t));
	va_list   args;
	va_start(args, fmt);
	int n = vsnprintf(line + head, sizeof(line) - 2 - head, fmt, args);
	va_end(args);
	if (n < 0) {
		return;
	}
	n = std::min(n + head, static_cast<int>(sizeof(line)) - 2);
	line[n++] = '\n';
	std::lock_guard<std::mutex> lock(g_log_lock);
	struct stat st {};
	if (fstat(g_log, &st) == 0 && st.st_size > kLogMaxSize) {
		(void)ftruncate(g_log, 0);
		(void)lseek(g_log, 0, SEEK_SET);
	}
	(void)write(g_log, line, static_cast<size_t>(n));
}

void notify(const char* text) {
	send_notification(text, true);
}

void notify_plain(const char* text) {
	send_notification(text, false);
}

std::vector<Video> list_videos() {
	std::vector<Video> all;
	auto scan = [&](const std::string& folder, const std::string& where) {
		DIR* dir = opendir(folder.c_str());
		if (dir == nullptr) {
			return;
		}
		std::vector<Video> found;
		while (dirent* e = readdir(dir)) {
			if (is_mp4(e->d_name)) {
				found.push_back({folder + "/" + e->d_name, e->d_name, where});
			}
		}
		closedir(dir);
		std::sort(found.begin(), found.end(), [](const Video& a, const Video& b) {
			return strcasecmp(a.name.c_str(), b.name.c_str()) < 0;
		});
		all.insert(all.end(), found.begin(), found.end());
	};
	scan("/data/LiveShell/video", "Internal");
	// USB: a folder called liveshell in any capitalisation (the drive's file system is case
	// sensitive here), clips directly inside it and/or in a "video" subfolder.
	auto subdir = [](const std::string& parent, const char* want) {
		std::string found;
		if (DIR* dir = opendir(parent.c_str())) {
			while (dirent* e = readdir(dir)) {
				if (strcasecmp(e->d_name, want) == 0) {
					found = parent + "/" + e->d_name;
					break;
				}
			}
			closedir(dir);
		}
		return found;
	};
	for (int i = 0; i < 8; ++i) {
		const std::string where = "USB " + std::to_string(i + 1);
		const std::string root  = subdir("/mnt/usb" + std::to_string(i), "liveshell");
		if (root.empty()) {
			continue;
		}
		scan(root, where);
		const std::string video = subdir(root, "video");
		if (!video.empty()) {
			scan(video, where);
		}
	}
	return all;
}

// The console's LAN address: a UDP "connect" picks the outgoing interface without sending anything.
std::string lan_ip() {
	const int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return {};
	}
	sockaddr_in to {};
	to.sin_family      = AF_INET;
	to.sin_port        = htons(53);
	to.sin_addr.s_addr = htonl(0x08080808);
	sockaddr_in me {};
	socklen_t   len = sizeof(me);
	char        ip[INET_ADDRSTRLEN] = {};
	if (connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0 &&
	    getsockname(s, reinterpret_cast<sockaddr*>(&me), &len) == 0) {
		inet_ntop(AF_INET, &me.sin_addr, ip, sizeof(ip));
	}
	close(s);
	return ip;
}

State get_state() {
	State st;
	st.ip = lan_ip();
	{
		std::lock_guard<std::mutex> lock(g_ctl);
		st.enabled = g_enabled;
		st.current = g_current;
		st.dim     = g_dim;
		st.blur    = g_blur;
		for (int l = 0; l < 4; ++l) {
			st.looks[l] = g_looks[l];
		}
		st.shuffle    = g_shuffle;
		st.game_pause = g_game_pause;
		st.menu_hide  = g_menu_hide;
		st.parallax   = g_parallax;
		st.game       = g_game_running ? g_game_title : std::string();
	}
	st.status = shellui_status();
	st.videos = list_videos();
	return st;
}

bool select_video(const std::string& path, std::string& error) {
	if (!exists(path.c_str())) {
		error = "That video is gone";
		return false;
	}
	std::lock_guard<std::mutex> lock(g_ctl);
	g_current = path;
	g_enabled = true;
	save_config();
	return apply_locked(error);
}

void set_dim(int percent) {
	std::lock_guard<std::mutex> lock(g_ctl);
	g_dim = std::max(0, std::min(80, percent));
	save_config();
	write_text(kDimFile, std::to_string(g_dim) + "\n");
	log("dim: %d%%", g_dim);
}

void set_look(const std::string& key, int level) {
	static const char* const kKeys[4] = {"bottom", "top", "vignette", "haze"};
	std::lock_guard<std::mutex> lock(g_ctl);
	for (int l = 0; l < 4; ++l) {
		if (key == kKeys[l]) {
			g_looks[l] = std::max(0, std::min(2, level));
			save_config();
			write_looks();
			log("look %s: %d", kKeys[l], g_looks[l]);
		}
	}
}

void set_blur(int level) {
	std::lock_guard<std::mutex> lock(g_ctl);
	g_blur = std::max(0, std::min(2, level));
	save_config();
	write_text(kBlurFile, std::to_string(g_blur) + "\n");
	log("blur: %d", g_blur);
}

bool set_enabled(bool on, std::string& error) {
	std::lock_guard<std::mutex> lock(g_ctl);
	g_enabled = on;
	if (on && (g_current.empty() || !exists(g_current.c_str()))) {
		const std::vector<Video> videos = list_videos();
		g_current = videos.empty() ? std::string() : videos.front().path;
	}
	save_config();
	return apply_locked(error);
}

bool set_option(const std::string& key, bool on, std::string& error) {
	std::lock_guard<std::mutex> lock(g_ctl);
	if (key == "shuffle") {
		g_shuffle = on;
	} else if (key == "gamepause") {
		g_game_pause = on;
	} else if (key == "parallax") {
		g_parallax = on;
		write_text(kParallaxFile, on ? "1\n" : "0\n");
	} else if (key == "menuhide") {
		g_menu_hide = on;
		write_text(kMenusFile, on ? "1\n" : "0\n");
	} else {
		error = "Unknown setting";
		return false;
	}
	save_config();
	log("option %s=%d", key.c_str(), on ? 1 : 0);
	// Pausing for a game that is running right now takes effect at once.
	return key != "gamepause" || !g_game_running || !g_injected || apply_locked(error);
}

bool delete_video(const std::string& path, std::string& error) {
	std::lock_guard<std::mutex> lock(g_ctl);
	if (path == g_current) {
		// Release it on the home screen first: switch to another clip (or off).
		std::string next;
		for (const Video& v : list_videos()) {
			if (v.path != path) {
				next = v.path;
				break;
			}
		}
		g_current = next;
		save_config();
		if (!apply_locked(error)) {
			return false;
		}
	}
	const std::string cover = path.substr(0, path.rfind('.')) + ".png";
	const bool        ok    = unlink(path.c_str()) == 0;
	unlink(cover.c_str());
	log("delete %s: %s", path.c_str(), ok ? "done" : strerror(errno));
	if (!ok) {
		error = "The file could not be deleted";
	}
	return ok;
}

bool reset_settings(std::string& error) {
	std::lock_guard<std::mutex> lock(g_ctl);
	g_enabled    = true;
	g_dim        = 25;
	g_blur       = 0;
	for (int& v : g_looks) {
		v = 0;
	}
	write_looks();
	g_shuffle    = false;
	g_game_pause = true;
	g_menu_hide  = true;
	g_parallax   = false;
	write_text(kParallaxFile, "0\n");
	write_text(kMenusFile, "1\n");
	if (g_current.empty() || !exists(g_current.c_str())) {
		const std::vector<Video> videos = list_videos();
		g_current = videos.empty() ? std::string() : videos.front().path;
	}
	save_config();
	write_text(kDimFile, std::to_string(g_dim) + "\n");
	write_text(kBlurFile, "0\n");
	log("settings reset");
	return apply_locked(error);
}

void request_shutdown() {
	log("shutdown requested from the window");
	g_stop_requested = true;
	g_running        = false;
}

// A game (not a system app, not our own window) is running: no video, the game gets the decoder.
void* game_thread(void*) {
	bool last = false;
	while (g_running) {
		sleep(2);
		const int   app = sceSystemServiceGetAppIdOfRunningBigApp();
		char        id[32] {};
		const bool  now = app >= 0 && sceSystemServiceGetAppTitleId(app, id) == 0 && id[0] != 0 &&
		                 strncmp(id, "NPXS", 4) != 0 && strcmp(id, "LVSH00001") != 0;
		if (now == last) {
			continue;
		}
		last = now;
		std::lock_guard<std::mutex> lock(g_ctl);
		g_game_running = now;
		g_game_title   = now ? id : "";
		log("game %s (%s)", now ? "started" : "closed", now ? id : "-");
		if (g_game_pause && g_injected) {
			std::string error;
			if (!apply_locked(error)) {
				log("game pause: %s", error.c_str());
			}
		}
	}
	return nullptr;
}

} // namespace liveshell

using namespace liveshell;

int main() {
	mkdir("/data/LiveShell", 0777);
	mkdir("/data/LiveShell/video", 0777);
	mkdir("/system_tmp/liveshell", 0777);
	// Loading the payload = try again: a crash marker from an earlier run must not keep the video
	// off until the next reboot.
	unlink("/system_tmp/liveshell/video_trying");
	g_log = open(kLogFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	log("LiveShell starting");
	// The injector's own steps (attach / load / stager / detach) go here.
	unlink("/data/LiveShell/inject.log");
	onion_log_configure("liveshell", "/data/LiveShell/inject.log");
	onion_log_set_level(ONION_LOG_DEBUG);

	if (kOnionGuard && onion_daemon_answers()) {
		notify("LiveShell Engine can't run while OnionHEN is running.");
		return 1;
	}

	std::vector<Video> videos = list_videos();
	log("%zu video(s) found", videos.size());
	{
		std::lock_guard<std::mutex> lock(g_ctl);
		load_config();
		const bool chosen_ok = std::any_of(videos.begin(), videos.end(), [](const Video& v) { return v.path == g_current; });
		if (!chosen_ok) {
			g_current = videos.empty() ? std::string() : videos.front().path;
		}
		if (g_shuffle && videos.size() > 1) {
			// Random clip on every start, never the same one twice in a row.
			srand(static_cast<unsigned>(time(nullptr)) ^ static_cast<unsigned>(getpid()));
			std::vector<std::string> others;
			for (const Video& v : videos) {
				if (v.path != g_current) {
					others.push_back(v.path);
				}
			}
			g_current = others[static_cast<size_t>(rand()) % others.size()];
			save_config();
			log("shuffle: %s", g_current.c_str());
		}
		std::string error;
		apply_locked(error); // not injected yet: just mounts + writes the path file
	}
	if (videos.empty()) {
		notify_plain("No video found. Put an .mp4 in /data/LiveShell/video or in a liveshell folder on a USB drive.");
	}

	start_thread(stop_thread);
	start_web_server();

	pid_t last_pid = inject_shellui();
	if (last_pid < 0) {
		return 3;
	}
	{
		std::lock_guard<std::mutex> lock(g_ctl);
		g_injected = last_pid > 0;
	}
	start_thread(after_start_thread);
	start_thread(game_thread);

	// Re-inject after ShellUI restarts. A restart soon after an injection means our module crashed
	// it: stop for good instead of crash-looping the console.
	time_t injected_at = time(nullptr);
	while (g_running) {
		sleep(5);
		if (!g_running) {
			break;
		}
		const pid_t current = onion_find_pid("SceShellUI");
		if (current <= 0 || current == last_pid) {
			continue;
		}
		const long alive = static_cast<long>(time(nullptr) - injected_at);
		log("ShellUI restarted: was %d, now %d (%ld s after injection)", static_cast<int>(last_pid),
		    static_cast<int>(current), alive);
		copy_shellui_log();
		if (alive < kCrashWindowSec) {
			log("ShellUI died %ld s after injection: treating it as a crash, not re-injecting", alive);
			notify("LiveShell Engine stopped: the home screen crashed. Log: /data/LiveShell/liveshell.log");
			break;
		}
		sleep(3); // let the new ShellUI settle
		{
			std::lock_guard<std::mutex> lock(g_ctl);
			g_injected = false; // the new ShellUI has no module yet: no waiting for it to let go
			std::string error;
			apply_locked(error); // fresh sandbox: mount the window again
		}
		last_pid    = inject_shellui();
		injected_at = time(nullptr);
		if (last_pid <= 0) {
			break;
		}
		std::lock_guard<std::mutex> lock(g_ctl);
		g_injected = true;
	}

	copy_shellui_log();
	// With OnionHEN running, restarting ShellUI would take OnionHEN's toolbox down too. Soft stop
	// instead: video off, looks off, folder unmounted; the idle module stays parked in ShellUI and
	// the next start reuses it (the marker stays, so no second injection).
	const pid_t ui    = onion_find_pid("SceShellUI");
	const bool  onion = onion_daemon_answers() || (ui > 0 && read_pid_file(kOnionToolbox) == ui);
	if (g_stop_requested && onion) {
		write_text(kDimFile, "0\n");
		write_text(kBlurFile, "0\n");
		write_text(kLooksFile, "0 0 0 0\n");
		write_text(kParallaxFile, "0\n");
		write_text(kPathFile, "off\n");
		if (!wait_shellui_stopped(8000)) {
			log("soft stop: ShellUI still holds the video (%s)", shellui_status().c_str());
		}
		unmount_window_everywhere();
		log("LiveShell stopped (soft: OnionHEN keeps running, the idle module stays in ShellUI)");
		notify("LiveShell Engine stopped.");
		return 0;
	}
	write_text(kPathFile, "off\n");
	if (g_stop_requested) {
		restart_shellui();
		sleep(2);
	}
	unmount_window_everywhere();
	unlink(kOurMarker);
	unlink(kStatusFile);
	log("LiveShell stopped");
	notify("LiveShell Engine stopped.");
	return 0;
}
