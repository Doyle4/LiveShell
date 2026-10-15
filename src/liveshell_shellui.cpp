/*
 * liveshell_shellui.cpp — LiveShell: PS5 animated wallpaper, the part injected into SceShellUI.
 * The daemon (liveshell_daemon.cpp) injects this as an ELF. GPL-3.0; built on OnionHEN
 * (aydencharles/onionHEN) — its injector, detour library, and the way it drives ShellUI's Mono.
 *
 * Plays the user's video behind the home screen using Sony's own PUI.UI3.VideoView + Sce.Vsh.Video
 * VideoPlayer, added to the BGLayer scene (BGLayerPlugin.RootWidget). Hard-won rules:
 *   - every BGLayer/video call on ShellUI's UI thread (we detour PUI.Application.Update)
 *   - pin every Mono object we keep a raw pointer to (the GC moves objects)
 *   - never call VideoPlayer.GetPlayerStatus from the UI thread (deadlock)
 *   - SetLoop(true) on view.VideoPlayer a moment after start; if a loop still ends, Play(0)
 *   - Full HD video only (1080p, up to 60 fps); 4K does not open in ShellUI's player
 *
 * The daemon writes the clip path to /system_tmp/liveshell/video.txt (ShellUI cannot read /data; the
 * video folder is nullfs-mounted into the sandboxes at /system_ex/vsh_asset/wallpaper).
 * Log: /system_tmp/liveshell/shellui.log.
 */
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include <onion/detour.h>

extern "C" {
int       get_module_handle(pid_t pid, const char* module_name);
uintptr_t set_ucred_to_ptrace(void);
uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid);
int       sceKernelSendNotificationRequest(int, void*, size_t, int);
}

// libonion_detour reads these as weak externs that the host module must define. Left undefined,
// the weak symbol sits at address 0 and the first InstallDetour crashes ShellUI.
int (*sceKernelMprotect)(void* addr, size_t len, int prot) = nullptr;
bool has_hv_bypass = false;

namespace {

constexpr const char* kPathFile   = "/system_tmp/liveshell/video.txt";
constexpr const char* kLogFile    = "/system_tmp/liveshell/shellui.log";
constexpr const char* kGuardFile  = "/system_tmp/liveshell/video_trying";
constexpr const char* kStatusFile = "/system_tmp/liveshell/status.txt";
constexpr const char* kDimFile    = "/system_tmp/liveshell/dim.txt";
constexpr off_t       kLogMaxSize = 256 * 1024;

// ---- logging ---------------------------------------------------------------------------------
int  g_log   = -1;
long g_t0_ms = 0;
int  g_tick  = 0; // UI frames since injection

long now_ms() {
	timespec ts {};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<long>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

void wp_log(const char* fmt, ...) {
	if (g_log < 0) {
		return;
	}
	char line[1400];
	const int head = snprintf(line, sizeof(line), "[%6ld ms] ", now_ms() - g_t0_ms);
	va_list   args;
	va_start(args, fmt);
	int n = vsnprintf(line + head, sizeof(line) - 1 - head, fmt, args);
	va_end(args);
	if (n < 0) {
		return;
	}
	n += head;
	if (n > static_cast<int>(sizeof(line)) - 2) {
		n = static_cast<int>(sizeof(line)) - 2;
	}
	line[n++] = '\n';
	struct stat st {};
	if (fstat(g_log, &st) == 0 && st.st_size > kLogMaxSize) {
		(void)ftruncate(g_log, 0);
		(void)lseek(g_log, 0, SEEK_SET);
	}
	(void)write(g_log, line, static_cast<size_t>(n));
}

// What the daemon sees: playing <path> / starting / stopping / stopped / failed <rc>.
void write_status(const char* fmt, ...) {
	char    text[600];
	va_list args;
	va_start(args, fmt);
	const int n = vsnprintf(text, sizeof(text) - 1, fmt, args);
	va_end(args);
	if (n < 0) {
		return;
	}
	const size_t len = strlen(text);
	text[len]        = '\n';
	const int fd     = open(kStatusFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd >= 0) {
		(void)write(fd, text, len + 1);
		close(fd);
	}
	text[len] = 0;
	wp_log("status: %s", text);
}

void notify(const char* text) {
	struct {
		char unused[45];
		char message[3075];
	} req = {};
	snprintf(req.message, sizeof(req.message), "%s", text);
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

// ---- Mono ------------------------------------------------------------------------------------
using Obj = void*;
Obj    (*mono_get_root_domain)();
Obj    (*mono_thread_attach)(Obj domain);
Obj    (*mono_domain_assembly_open)(Obj domain, const char* name);
Obj    (*mono_assembly_get_image)(Obj assembly);
Obj    (*mono_class_from_name)(Obj image, const char* name_space, const char* name);
Obj    (*mono_class_get_method_from_name)(Obj klass, const char* name, int param_count);
Obj    (*mono_class_get_property_from_name)(Obj klass, const char* name);
Obj    (*mono_class_get_field_from_name)(Obj klass, const char* name);
Obj    (*mono_class_get_parent)(Obj klass);
Obj    (*mono_property_get_get_method)(Obj prop);
Obj    (*mono_property_get_set_method)(Obj prop);
Obj    (*mono_runtime_invoke)(Obj method, Obj obj, void** params, Obj* exc);
Obj    (*mono_object_new)(Obj domain, Obj klass);
Obj    (*mono_string_new)(Obj domain, const char* text);
void*  (*mono_object_unbox)(Obj obj);
Obj    (*mono_object_to_string)(Obj obj, Obj* exc);
char*  (*mono_string_to_utf8)(Obj str);
uint32_t (*mono_gchandle_new)(Obj obj, int pinned);
Obj    (*mono_method_desc_new)(const char* name, int include_namespace);
Obj    (*mono_method_desc_search_in_class)(Obj desc, Obj klass);
void   (*mono_method_desc_free)(Obj desc);
void*  (*mono_compile_method)(Obj method);
void   (*mono_field_get_value)(Obj obj, Obj field, void* value);
void   (*mono_field_set_value)(Obj obj, Obj field, void* value);
Obj    (*mono_get_corlib)();
void*  (*mono_class_get_type)(Obj klass);
Obj    (*mono_type_get_object)(Obj domain, void* type);
Obj    (*mono_method_get_object)(Obj domain, Obj method, Obj klass);
// Optional (diagnostics only): list a class's properties.
Obj         (*mono_class_get_properties)(Obj klass, void** iter);
const char* (*mono_property_get_name)(Obj prop);
Obj         (*mono_class_get_methods)(Obj klass, void** iter);
const char* (*mono_method_get_name)(Obj method);
int         (*mono_image_get_table_rows)(Obj image, int table);
Obj         (*mono_object_get_class)(Obj obj);
Obj         (*mono_class_get_fields)(Obj klass, void** iter);
const char* (*mono_field_get_name)(Obj field);
Obj         (*mono_method_signature)(Obj method);
Obj         (*mono_signature_get_return_type)(Obj sig);
char*       (*mono_type_get_name)(Obj type);
Obj         (*mono_class_from_mono_type)(Obj type);
int         (*mono_class_is_enum)(Obj klass);
Obj         (*mono_class_vtable)(Obj domain, Obj klass);
void        (*mono_field_static_get_value)(Obj vtable, Obj field, void* value);
Obj         (*mono_signature_get_params)(Obj sig, void** iter);
void        (*mono_method_get_param_names)(Obj method, const char** names);
Obj         (*mono_class_get)(Obj image, uint32_t token);
const char* (*mono_class_get_name)(Obj klass);

std::atomic<const char*> g_step{"start"};

// Heartbeat: if our thread crashes at a step, the heartbeat stops at the same moment; if it is stuck
// in a step while ShellUI keeps running until something kills it, the heartbeat keeps going.
void* heartbeat_thread(void*) {
	for (int i = 0; i < 100; ++i) {
		wp_log("heartbeat, step: %s", g_step.load());
		usleep(i < 40 ? 250 * 1000 : 1000 * 1000);
	}
	return nullptr;
}

template <typename T>
bool resolve(int handle, T& fn, const char* name) {
	g_step.store(name);
	fn = reinterpret_cast<T>(kernel_dynlib_dlsym(-1, static_cast<uint32_t>(handle), name));
	if (fn == nullptr) {
		wp_log("missing Mono symbol: %s", name);
	}
	return fn != nullptr;
}
#define RESOLVE(f) ok &= resolve(lib, f, #f)

// Caller holds the raised authid (get_module_handle / dlsym across modules need it).
bool resolve_kernel() {
	g_step.store("get_module_handle(libkernel_sys)");
	const int lib = get_module_handle(getpid(), "libkernel_sys.sprx");
	if (lib <= 0) {
		wp_log("libkernel_sys handle %d", lib);
		return false;
	}
	sceKernelMprotect = reinterpret_cast<int (*)(void*, size_t, int)>(
	    kernel_dynlib_dlsym(-1, static_cast<uint32_t>(lib), "sceKernelMprotect"));
	wp_log("libkernel_sys handle %d, sceKernelMprotect %p", lib, reinterpret_cast<void*>(sceKernelMprotect));
	return sceKernelMprotect != nullptr;
}

bool resolve_mono() {
	g_step.store("get_module_handle(libmonosgen)");
	wp_log("looking up libmonosgen");
	const int lib = get_module_handle(getpid(), "libmonosgen-2.0.sprx");
	wp_log("libmonosgen handle %d, resolving symbols", lib);
	bool            ok         = lib > 0;
	if (ok) {
		RESOLVE(mono_get_root_domain);
		RESOLVE(mono_thread_attach);
		RESOLVE(mono_domain_assembly_open);
		RESOLVE(mono_assembly_get_image);
		RESOLVE(mono_class_from_name);
		RESOLVE(mono_class_get_method_from_name);
		RESOLVE(mono_class_get_property_from_name);
		RESOLVE(mono_class_get_field_from_name);
		RESOLVE(mono_class_get_parent);
		RESOLVE(mono_property_get_get_method);
		RESOLVE(mono_property_get_set_method);
		RESOLVE(mono_runtime_invoke);
		RESOLVE(mono_object_new);
		RESOLVE(mono_string_new);
		RESOLVE(mono_object_unbox);
		RESOLVE(mono_object_to_string);
		RESOLVE(mono_string_to_utf8);
		RESOLVE(mono_gchandle_new);
		RESOLVE(mono_method_desc_new);
		RESOLVE(mono_method_desc_search_in_class);
		RESOLVE(mono_method_desc_free);
		RESOLVE(mono_compile_method);
		RESOLVE(mono_field_get_value);
		RESOLVE(mono_field_set_value);
		RESOLVE(mono_get_corlib);
		RESOLVE(mono_class_get_type);
		RESOLVE(mono_type_get_object);
		RESOLVE(mono_method_get_object);
		resolve(lib, mono_class_get_properties, "mono_class_get_properties");
		resolve(lib, mono_property_get_name, "mono_property_get_name");
		resolve(lib, mono_class_get_methods, "mono_class_get_methods");
		resolve(lib, mono_method_get_name, "mono_method_get_name");
		resolve(lib, mono_image_get_table_rows, "mono_image_get_table_rows");
		resolve(lib, mono_object_get_class, "mono_object_get_class");
		resolve(lib, mono_class_get_fields, "mono_class_get_fields");
		resolve(lib, mono_field_get_name, "mono_field_get_name");
		resolve(lib, mono_method_signature, "mono_method_signature");
		resolve(lib, mono_signature_get_return_type, "mono_signature_get_return_type");
		resolve(lib, mono_type_get_name, "mono_type_get_name");
		resolve(lib, mono_class_from_mono_type, "mono_class_from_mono_type");
		resolve(lib, mono_class_is_enum, "mono_class_is_enum");
		resolve(lib, mono_class_vtable, "mono_class_vtable");
		resolve(lib, mono_field_static_get_value, "mono_field_static_get_value");
		resolve(lib, mono_signature_get_params, "mono_signature_get_params");
		resolve(lib, mono_method_get_param_names, "mono_method_get_param_names");
		resolve(lib, mono_class_get, "mono_class_get");
		resolve(lib, mono_class_get_name, "mono_class_get_name");
	}
	wp_log("libmonosgen handle %d, symbols %s", lib, ok ? "ok" : "MISSING");
	return ok;
}

#undef RESOLVE

Obj g_domain = nullptr;

// ---- Mono helpers ----------------------------------------------------------------------------

void log_exception(const char* what, Obj exc) {
	if (exc == nullptr) {
		return;
	}
	Obj         inner = nullptr;
	Obj         text  = mono_object_to_string(exc, &inner);
	const char* utf8  = text != nullptr ? mono_string_to_utf8(static_cast<char*>(text)) : nullptr;
	wp_log("%s threw: %s", what, utf8 != nullptr ? utf8 : "(no text)");
}

bool invoke(Obj method, Obj obj, void** args, const char* what, Obj* result = nullptr) {
	if (method == nullptr) {
		wp_log("no method for %s", what);
		return false;
	}
	Obj exc = nullptr;
	Obj ret = mono_runtime_invoke(method, obj, args, &exc);
	log_exception(what, exc);
	if (result != nullptr) {
		*result = exc == nullptr ? ret : nullptr;
	}
	return exc == nullptr;
}

Obj property_get(Obj klass, Obj obj, const char* name) {
	Obj prop = mono_class_get_property_from_name(klass, name);
	Obj get  = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
	if (get == nullptr) {
		wp_log("no getter %s", name);
		return nullptr;
	}
	Obj exc    = nullptr;
	Obj result = mono_runtime_invoke(get, obj, nullptr, &exc);
	log_exception(name, exc);
	return exc != nullptr ? nullptr : result;
}

bool property_set(Obj klass, Obj obj, const char* name, void* value) {
	Obj prop = mono_class_get_property_from_name(klass, name);
	Obj set  = prop != nullptr ? mono_property_get_set_method(prop) : nullptr;
	if (set == nullptr) {
		wp_log("no setter %s", name);
		return false;
	}
	void* args[1] = {value};
	Obj   exc     = nullptr;
	mono_runtime_invoke(set, obj, args, &exc);
	log_exception(name, exc);
	return exc == nullptr;
}

Obj open_image(const char* path) {
	Obj assembly = mono_domain_assembly_open(g_domain, path);
	Obj image    = assembly != nullptr ? mono_assembly_get_image(assembly) : nullptr;
	if (image == nullptr) {
		wp_log("cannot open assembly %s", path);
	}
	return image;
}

uint64_t get_method_address(Obj image, const char* name_space, const char* class_name,
                            const char* method_name, int param_count) {
	Obj klass = mono_class_from_name(image, name_space, class_name);
	if (klass == nullptr) {
		wp_log("class %s.%s not found", name_space, class_name);
		return 0;
	}
	Obj method = mono_class_get_method_from_name(klass, method_name, param_count);
	if (method == nullptr) {
		wp_log("method %s.%s.%s(%d) not found", name_space, class_name, method_name, param_count);
		return 0;
	}
	return reinterpret_cast<uint64_t>(mono_compile_method(method));
}

Obj find_method_up(Obj klass, const char* name, int argc) {
	for (Obj k = klass; k != nullptr; k = mono_class_get_parent != nullptr ? mono_class_get_parent(k) : nullptr) {
		Obj m = mono_class_get_method_from_name(k, name, argc);
		if (m != nullptr) {
			return m;
		}
	}
	return nullptr;
}

Obj method_by_desc(Obj klass, const char* desc_text) {
	Obj desc   = mono_method_desc_new(desc_text, 1);
	Obj method = desc != nullptr ? mono_method_desc_search_in_class(desc, klass) : nullptr;
	if (desc != nullptr) {
		mono_method_desc_free(desc);
	}
	if (method == nullptr) {
		wp_log("method %s not found", desc_text);
	}
	return method;
}

Obj construct_pinned(Obj klass, Obj ctor, void** args, const char* what) {
	Obj obj = mono_object_new(g_domain, klass);
	if (obj == nullptr) {
		return nullptr;
	}
	mono_gchandle_new(obj, 1);
	if (!invoke(ctor, obj, args, what)) {
		return nullptr;
	}
	return obj;
}

// ---- BGLayer setup ---------------------------------------------------------------------------
bool g_installed = false;
Obj  g_plugin    = nullptr;

int install_bglayer() {
	Obj image = open_image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.BGLayer.dll");
	if (image == nullptr) {
		return 2;
	}
	Obj plugin_class = mono_class_from_name(image, "Sce.Vsh.ShellUI.BGLayer", "BGLayerPlugin");
	if (plugin_class == nullptr) {
		wp_log("BGLayerPlugin class not found");
		return 3;
	}
	g_plugin = property_get(plugin_class, nullptr, "Instance");
	if (g_plugin == nullptr) {
		wp_log("BGLayerPlugin.Instance is null");
		return 4;
	}
	mono_gchandle_new(g_plugin, 1);
	g_installed = true;
	return 0;
}

// ---- noop Action (for PlayStateChanged) ------------------------------------------------------

Obj make_noop_action() {
	Obj corlib         = mono_get_corlib();
	Obj action_class   = mono_class_from_name(corlib, "System", "Action");
	Obj thread_class   = mono_class_from_name(corlib, "System.Threading", "Thread");
	Obj delegate_class = mono_class_from_name(corlib, "System", "Delegate");
	if (action_class == nullptr || thread_class == nullptr || delegate_class == nullptr) {
		return nullptr;
	}
	Obj barrier = mono_class_get_method_from_name(thread_class, "MemoryBarrier", 0);
	Obj desc    = mono_method_desc_new(":CreateDelegate(System.Type,System.Reflection.MethodInfo)", 1);
	Obj create  = desc != nullptr ? mono_method_desc_search_in_class(desc, delegate_class) : nullptr;
	if (desc != nullptr) {
		mono_method_desc_free(desc);
	}
	if (barrier == nullptr || create == nullptr) {
		return nullptr;
	}
	void* args[2] = {mono_type_get_object(g_domain, mono_class_get_type(action_class)),
	                 mono_method_get_object(g_domain, barrier, thread_class)};
	Obj action = nullptr;
	invoke(create, nullptr, args, "Delegate.CreateDelegate", &action);
	if (action != nullptr) {
		mono_gchandle_new(action, 1);
	}
	return action;
}

// ---- video: InitialBootPlayer route ----------------------------------------------------------
// Sony's own boot-movie widget drives the whole VideoView lifecycle itself. We redirect its
// private GetVideoPath to our clip (for our instance only) and let it handle Create/Play/loop.

char g_video_path[512] = {};
bool g_mode_sony       = false;

Obj  g_boot_class      = nullptr;
Obj  g_boot_player     = nullptr;
Obj  g_boot_root       = nullptr;
Obj  g_widget_class    = nullptr;
Obj  g_videoview_class = nullptr;
Obj  g_vplayer_class   = nullptr;
Obj  g_state_field     = nullptr;
Obj  g_state_action    = nullptr;
int  g_boot_frames     = 0;
int  g_boot_state      = -1;
int  g_boot_restarts   = 0;
int  g_boot_quick      = 0;
int  g_boot_started    = 0;

int  g_boot_end_frame      = -1;
int  g_boot_dispose_frame  = -1;
bool g_boot_dispose_called = false;
bool g_boot_loop_set       = false;

using VoidMethodFn = void (*)(Obj self);
VoidMethodFn g_on_end_orig       = nullptr;
VoidMethodFn g_dispose_self_orig = nullptr;

void OnEnd_Hook(Obj self) {
	g_on_end_orig(self);
	if (self != nullptr && self == g_boot_player) {
		g_boot_end_frame = g_boot_frames;
		if (g_boot_restarts < 6) {
			wp_log("video: OnEnd (frame %d, %d after start)", g_boot_frames, g_boot_frames - g_boot_started);
		}
	}
}

void DisposeSelf_Hook(Obj self) {
	const bool ours = self != nullptr && self == g_boot_player;
	g_dispose_self_orig(self);
	if (ours) {
		g_boot_dispose_frame = g_boot_frames;
		if (g_boot_restarts < 6) {
			wp_log("video: DisposeSelf (frame %d)", g_boot_frames);
		}
	}
}

using GetVideoPathFn = void (*)(Obj self, Obj* path, Obj* content_type);
GetVideoPathFn g_get_video_path_orig = nullptr;
int g_path_calls = 0;

void GetVideoPath_Hook(Obj self, Obj* path, Obj* content_type) {
	const bool ours = self != nullptr && self == g_boot_player;
	if (ours) {
		*path         = mono_string_new(g_domain, g_video_path);
		*content_type = mono_string_new(g_domain, "video/mp4");
	} else {
		g_get_video_path_orig(self, path, content_type);
	}
	if (++g_path_calls <= 12) {
		const char* given = (path != nullptr && *path != nullptr)
		                        ? mono_string_to_utf8(static_cast<char*>(*path))
		                        : nullptr;
		wp_log("GetVideoPath #%d self %p ours %d -> %s", g_path_calls,
		       self, ours ? 1 : 0, given != nullptr ? given : "(null)");
	}
}

int create_boot_player() {
	wp_log("video: creating InitialBootPlayer");
	void* ctor_args[1] = {g_boot_root};
	Obj   player       = mono_object_new(g_domain, g_boot_class);
	if (player == nullptr ||
	    !invoke(mono_class_get_method_from_name(g_boot_class, ".ctor", 1), player, ctor_args,
	            "InitialBootPlayer()")) {
		return 31;
	}
	mono_gchandle_new(player, 1);
	g_boot_player = player;

	if (g_state_action != nullptr) {
		Obj field = mono_class_get_field_from_name(g_boot_class, "PlayStateChanged");
		if (field != nullptr) {
			mono_field_set_value(player, field, g_state_action);
		}
	}
	Obj parent = property_get(g_widget_class, player, "Parent");
	if (parent == nullptr) {
		void* child_args[1] = {player};
		invoke(mono_class_get_method_from_name(g_widget_class, "AppendChild", 1), g_boot_root,
		       child_args, "AppendChild");
	}
	float zero = 0.0f, width = 1920.0f, height = 1080.0f;
	property_set(g_widget_class, player, "X", &zero);
	property_set(g_widget_class, player, "Y", &zero);
	property_set(g_widget_class, player, "Width", &width);
	property_set(g_widget_class, player, "Height", &height);

	if (!invoke(mono_class_get_method_from_name(g_boot_class, "Create", 0), player, nullptr,
	            "InitialBootPlayer.Create")) {
		return 32;
	}
	if (g_videoview_class != nullptr) {
		uint8_t overwrite = 3;
		property_set(g_videoview_class, player, "BlendMode", &overwrite);
	}
	g_boot_state         = -1;
	g_boot_started       = g_boot_frames;
	g_boot_end_frame     = -1;
	g_boot_dispose_frame = -1;
	g_boot_dispose_called = false;
	g_boot_loop_set       = false;
	return 0;
}

int start_video_sony() {
	Obj bg  = open_image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.BGLayer.dll");
	Obj pui = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
	if (bg == nullptr || pui == nullptr) {
		return 21;
	}
	g_boot_class      = mono_class_from_name(bg, "Sce.Vsh.ShellUI.BGLayer", "InitialBootPlayer");
	g_widget_class    = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Widget");
	g_videoview_class = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "VideoView");
	Obj vp_image      = open_image("/system_ex/common_ex/lib/Sce.Vsh.VideoPlayer.dll");
	g_vplayer_class   = vp_image != nullptr
	                        ? mono_class_from_name(vp_image, "Sce.Vsh.Video", "VideoPlayer")
	                        : nullptr;
	g_state_field     = mono_class_get_field_from_name(g_boot_class, "state");
	Obj scene_class   = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Scene");
	if (g_boot_class == nullptr || g_widget_class == nullptr || scene_class == nullptr) {
		wp_log("video: classes boot %p widget %p scene %p",
		       g_boot_class, g_widget_class, scene_class);
		return 22;
	}

	const uint64_t target =
	    get_method_address(bg, "Sce.Vsh.ShellUI.BGLayer", "InitialBootPlayer", "GetVideoPath", 2);
	if (target == 0 ||
	    !InstallDetour(target, reinterpret_cast<void*>(&GetVideoPath_Hook),
	                   reinterpret_cast<void**>(&g_get_video_path_orig)) ||
	    g_get_video_path_orig == nullptr) {
		wp_log("video: GetVideoPath detour failed (target %#lx)", static_cast<unsigned long>(target));
		return 23;
	}
	const uint64_t on_end =
	    get_method_address(bg, "Sce.Vsh.ShellUI.BGLayer", "InitialBootPlayer", "OnEnd", 0);
	const uint64_t dispose =
	    get_method_address(bg, "Sce.Vsh.ShellUI.BGLayer", "InitialBootPlayer", "DisposeSelf", 0);
	if (on_end == 0 || dispose == 0 ||
	    !InstallDetour(on_end, reinterpret_cast<void*>(&OnEnd_Hook),
	                   reinterpret_cast<void**>(&g_on_end_orig)) ||
	    !InstallDetour(dispose, reinterpret_cast<void*>(&DisposeSelf_Hook),
	                   reinterpret_cast<void**>(&g_dispose_self_orig)) ||
	    g_on_end_orig == nullptr || g_dispose_self_orig == nullptr) {
		wp_log("video: OnEnd/DisposeSelf detour failed (%#lx %#lx)",
		       static_cast<unsigned long>(on_end), static_cast<unsigned long>(dispose));
		return 25;
	}

	g_boot_root = property_get(scene_class, g_plugin, "RootWidget");
	if (g_boot_root == nullptr) {
		return 24;
	}
	mono_gchandle_new(g_boot_root, 1);
	g_state_action = make_noop_action();
	wp_log("video: InitialBootPlayer route ready, GetVideoPath hooked, action %p", g_state_action);

	const int rc = create_boot_player();
	if (rc == 0) {
		wp_log("video: InitialBootPlayer created for %s", g_video_path);
	}
	return rc;
}

// ---- video: own player route -----------------------------------------------------------------
// VideoPlayer(CreateOptionParam) + VideoView(PlayOptionParam). Everything pinned, on the UI
// thread, no per-frame calls into VideoPlayer. SetLoop on view.VideoPlayer once it exists.

Obj g_own_player   = nullptr;
Obj g_own_view     = nullptr;
Obj g_own_play0    = nullptr;
int g_own_frames   = 0;
int g_own_logs     = 0;
int g_own_restarts = 0;
bool g_own_loop_set = false;

int start_own_player() {
	Obj pui   = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
	Obj video = open_image("/system_ex/common_ex/lib/Sce.Vsh.VideoPlayer.dll");
	if (pui == nullptr || video == nullptr) {
		return 40;
	}
	Obj view_class   = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "VideoView");
	Obj option_class = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "VideoView/PlayOptionParam");
	Obj player_class = mono_class_from_name(video, "Sce.Vsh.Video", "VideoPlayer");
	Obj create_class = mono_class_from_name(video, "Sce.Vsh.Video", "VideoPlayer/CreateOptionParam");
	Obj widget_class = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Widget");
	Obj scene_class  = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Scene");
	if (view_class == nullptr || option_class == nullptr || player_class == nullptr ||
	    create_class == nullptr || widget_class == nullptr || scene_class == nullptr) {
		wp_log("own player: classes missing");
		return 41;
	}
	g_videoview_class = view_class;

	Obj     uri          = mono_string_new(g_domain, g_video_path);
	Obj     content_type = mono_string_new(g_domain, "video/mp4");
	Obj     user_agent   = mono_string_new(g_domain, "");
	// coreType BE, playback, 1920x1080 output, canvas, FullHD decoder (ShellUI gets no UHD decoder;
	// 4K is for a later release, see PROGRESS.md "4K test").
	int     core_type = 1, create_mode = 1, frame_size = 1, render_buffer = 0, core_resource = 3;
	int     on_active = 4, on_inactive = 2, handler_mode = 0;
	uint32_t device_id = 0;
	void*   create_args[12] = {uri,            &core_type,     &create_mode,  &frame_size,
	                           &render_buffer,  &core_resource, content_type,  &on_active,
	                           &on_inactive,    &handler_mode,  user_agent,    &device_id};
	Obj create_opt = construct_pinned(
	    create_class, mono_class_get_method_from_name(create_class, ".ctor", 12),
	    create_args, "CreateOptionParam");
	if (create_opt == nullptr) {
		return 42;
	}

	void* player_args[1] = {create_opt};
	Obj   player         = construct_pinned(
	    player_class,
	    method_by_desc(player_class, ":.ctor(Sce.Vsh.Video.VideoPlayer/CreateOptionParam)"),
	    player_args, "VideoPlayer");
	if (player == nullptr) {
		return 43;
	}

	Obj option = construct_pinned(
	    option_class, mono_class_get_method_from_name(option_class, ".ctor", 0),
	    nullptr, "PlayOptionParam");
	if (option == nullptr) {
		return 44;
	}

	void* view_args[1] = {option};
	Obj   view         = construct_pinned(
	    view_class,
	    method_by_desc(view_class, ":.ctor(Sce.PlayStation.PUI.UI3.VideoView/PlayOptionParam)"),
	    view_args, "VideoView");
	if (view == nullptr) {
		return 45;
	}

	float   zero = 0.0f, width = 1920.0f, height = 1080.0f;
	uint8_t overwrite = 3;
	property_set(widget_class, view, "X", &zero);
	property_set(widget_class, view, "Y", &zero);
	property_set(widget_class, view, "Width", &width);
	property_set(widget_class, view, "Height", &height);
	property_set(widget_class, view, "Opacity", &zero); // focus_tick fades it in
	property_set(view_class, view, "BlendMode", &overwrite);

	bool  update_player      = true;
	void* set_player_args[2] = {player, &update_player};
	if (!invoke(mono_class_get_method_from_name(view_class, "SetPlayer", 2), view, set_player_args,
	            "SetPlayer")) {
		return 46;
	}

	Obj root = property_get(scene_class, g_plugin, "RootWidget");
	if (root == nullptr) {
		return 47;
	}
	mono_gchandle_new(root, 1);
	void* child_args[1] = {view};
	if (!invoke(mono_class_get_method_from_name(widget_class, "AppendChild", 1), root, child_args,
	            "AppendChild")) {
		return 48;
	}

	bool  load         = true;
	void* init_args[1] = {&load};
	invoke(mono_class_get_method_from_name(player_class, "Init", 1), player, init_args, "Init");
	if (!invoke(mono_class_get_method_from_name(view_class, "Play", 0), view, nullptr,
	            "VideoView.Play")) {
		return 49;
	}

	bool  loop         = true;
	void* loop_args[1] = {&loop};
	invoke(mono_class_get_method_from_name(player_class, "SetLoop", 1), player, loop_args,
	       "SetLoop");

	g_own_player    = player;
	g_own_view      = view;
	g_own_play0     = method_by_desc(view_class, ":Play(ulong)");
	g_vplayer_class = player_class;
	wp_log("own player: playing %s (loop, opaque, pinned)", g_video_path);
	return 0;
}

// ---- UI-thread tick: loop the Sony-route player ----------------------------------------------

void video_report() {
	if (g_boot_player == nullptr) {
		return;
	}
	++g_boot_frames;

	if (g_boot_frames % 120 == 60 && g_videoview_class != nullptr && g_boot_restarts < 2) {
		Obj pos = property_get(g_videoview_class, g_boot_player, "Position");
		Obj dur = property_get(g_videoview_class, g_boot_player, "Duration");
		wp_log("player: pos %llu dur %llu ms (frame %d)",
		       pos != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(pos)) : 0ULL,
		       dur != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(dur)) : 0ULL,
		       g_boot_frames - g_boot_started);
	}

	if (g_boot_frames % 30 == 0 && g_state_field != nullptr && g_boot_restarts < 6) {
		int state = -1;
		mono_field_get_value(g_boot_player, g_state_field, &state);
		if (state != g_boot_state) {
			wp_log("video: state %d (frame %d)", state, g_boot_frames - g_boot_started);
			g_boot_state = state;
		}
	}

	// SetLoop(true) on view.VideoPlayer once it exists — the seamless-loop fix.
	if (!g_boot_loop_set && g_vplayer_class != nullptr && g_boot_frames % 30 == 15) {
		Obj inner = property_get(g_videoview_class, g_boot_player, "VideoPlayer");
		if (inner != nullptr) {
			g_boot_loop_set    = true;
			bool  loop         = true;
			void* loop_args[1] = {&loop};
			const bool ok = invoke(mono_class_get_method_from_name(g_vplayer_class, "SetLoop", 1),
			                       inner, loop_args, "VideoPlayer.SetLoop");
			if (g_boot_restarts < 6) {
				wp_log("video: SetLoop(true) on view.VideoPlayer %s (frame %d)",
				       ok ? "ok" : "failed", g_boot_frames - g_boot_started);
			}
		}
	}

	// Fallback: Dispose the finished player 1.5 s after OnEnd, then recreate 30 frames later.
	if (g_boot_end_frame >= 0 && g_boot_dispose_frame < 0 && !g_boot_dispose_called &&
	    g_boot_frames - g_boot_end_frame >= 90) {
		g_boot_dispose_called = true;
		Obj dispose = find_method_up(g_boot_class, "Dispose", 0);
		if (g_boot_restarts < 6) {
			wp_log("video: disposing finished player (method %p)", dispose);
		}
		invoke(dispose, g_boot_player, nullptr, "Widget.Dispose");
		if (g_boot_dispose_frame < 0) {
			g_boot_dispose_frame = g_boot_frames;
		}
		return;
	}
	if (g_boot_dispose_frame < 0 || g_boot_frames - g_boot_dispose_frame < 30) {
		return;
	}
	if (g_boot_dispose_frame - g_boot_started < 120 && ++g_boot_quick >= 3) {
		wp_log("video: ends too fast, loop stopped");
		g_boot_player = nullptr;
		return;
	}
	++g_boot_restarts;
	const int rc = create_boot_player();
	if (g_boot_restarts <= 5) {
		wp_log("video: loop %d: new player (rc %d)", g_boot_restarts, rc);
	}
	if (rc != 0) {
		g_boot_player = nullptr;
	}
}

// ---- UI-thread tick: own-player route --------------------------------------------------------

void own_player_report() {
	if (g_own_view == nullptr) {
		return;
	}
	++g_own_frames;

	// SetLoop on the VideoView's own VideoPlayer once it appears.
	if (!g_own_loop_set && g_own_frames >= 15 && g_own_frames % 15 == 0 &&
	    g_vplayer_class != nullptr) {
		Obj inner = property_get(g_videoview_class, g_own_view, "VideoPlayer");
		if (inner != nullptr) {
			g_own_loop_set     = true;
			bool  loop         = true;
			void* loop_args[1] = {&loop};
			const bool ok = invoke(mono_class_get_method_from_name(g_vplayer_class, "SetLoop", 1),
			                       inner, loop_args, "VideoPlayer.SetLoop (view)");
			wp_log("own player: SetLoop(true) on view.VideoPlayer %s (frame %d, same %d)",
			       ok ? "ok" : "failed", g_own_frames, inner == g_own_player ? 1 : 0);
		}
	}

	// Fallback loop: only if the video is STUCK at the end (still there half a second later).
	// The player sits on the last frame for a moment before its own seamless loop; a Play(0) then
	// was a hard restart = visible quality drop at that loop (test 23).
	if (g_own_frames % 15 == 0 && g_own_play0 != nullptr) {
		Obj p = property_get(g_videoview_class, g_own_view, "Position");
		Obj d = property_get(g_videoview_class, g_own_view, "Duration");
		const unsigned long long pos =
		    p != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(p)) : 0;
		const unsigned long long dur =
		    d != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(d)) : 0;
		static int at_end = 0;
		at_end = dur > 0 && pos >= dur ? at_end + 1 : 0;
		if (at_end >= 3) {
			at_end = 0;
			unsigned long long zero = 0;
			void*              args[1] = {&zero};
			invoke(g_own_play0, g_own_view, args, "VideoView.Play(0)");
			if (++g_own_restarts <= 5) {
				wp_log("own player: at end (%llu/%llu), restarted from 0", pos, dur);
			}
		}
	}

	if (g_own_logs >= 15 || g_own_frames % 120 != 0) {
		return;
	}
	++g_own_logs;
	Obj pos = property_get(g_videoview_class, g_own_view, "Position");
	Obj dur = property_get(g_videoview_class, g_own_view, "Duration");
	wp_log("own player: pos %llu dur %llu ms",
	       pos != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(pos)) : 0ULL,
	       dur != nullptr ? *static_cast<unsigned long long*>(mono_object_unbox(dur)) : 0ULL);
}

// ---- dim layer: a black panel over the video so the home screen stays readable ----------------
// The BGLayer is a PUI.UI3 scene. Which UI3 class can draw a plain colour is not known for sure,
// so a few candidates are tried and their properties logged (the log tells the next build).

std::atomic<int>  g_dim_req{-1};
std::atomic<bool> g_dim_new{false};
Obj               g_dim_panel   = nullptr;
Obj               g_dim_root    = nullptr;
Obj               g_dim_class   = nullptr;
Obj               g_ui3_widget  = nullptr;
Obj               g_color_class = nullptr;
const char*       g_dim_prop    = nullptr; // the colour property that worked
bool              g_dim_tried   = false;
int               g_dim_shown   = -1;
float             g_black_now   = 0.0f;    // game launch: our dim panel going to black
Obj               g_blur_target = nullptr; // widget carrying the blur effect (dim panel or video view)

bool video_active();

void log_properties(Obj klass, const char* label) {
	if (mono_class_get_properties == nullptr || mono_property_get_name == nullptr) {
		return;
	}
	for (Obj k = klass; k != nullptr; k = mono_class_get_parent(k)) {
		char   line[1200];
		size_t n    = 0;
		void*  iter = nullptr;
		line[0]     = 0;
		while (Obj p = mono_class_get_properties(k, &iter)) {
			const char* name = mono_property_get_name(p);
			const int   w    = snprintf(line + n, sizeof(line) - n, "%s ", name != nullptr ? name : "?");
			if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
				break;
			}
			n += static_cast<size_t>(w);
		}
		wp_log("props %s (level %p): %s", label, k, line);
	}
}

// Probe for "home screen only": which BGLayer calls happen when Settings etc. open.
void log_methods(Obj klass, const char* label) {
	if (mono_class_get_methods == nullptr || mono_method_get_name == nullptr || klass == nullptr) {
		return;
	}
	char   line[1300];
	size_t n    = 0;
	void*  iter = nullptr;
	line[0]     = 0;
	while (Obj m = mono_class_get_methods(klass, &iter)) {
		const char* name = mono_method_get_name(m);
		const int   w    = snprintf(line + n, sizeof(line) - n, "%s ", name != nullptr ? name : "?");
		if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
			break;
		}
		n += static_cast<size_t>(w);
	}
	wp_log("methods %s: %s", label, line);
}

// Every class in the BGLayer assembly (type-definition table; row 1 is <Module>).
void log_all_classes(Obj image) {
	if (mono_image_get_table_rows == nullptr || mono_class_get == nullptr || mono_class_get_name == nullptr) {
		return;
	}
	const int rows = mono_image_get_table_rows(image, 2 /* MONO_TABLE_TYPEDEF */);
	char      line[1300];
	size_t    n = 0;
	line[0]     = 0;
	for (int i = 2; i <= rows; ++i) {
		Obj         k    = mono_class_get(image, 0x02000000u | static_cast<uint32_t>(i));
		const char* name = k != nullptr ? mono_class_get_name(k) : nullptr;
		const int   w    = snprintf(line + n, sizeof(line) - n, "%s ", name != nullptr ? name : "?");
		if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
			wp_log("classes BGLayer: %s", line);
			n       = 0;
			line[0] = 0;
			--i;
			continue;
		}
		n += static_cast<size_t>(w);
	}
	wp_log("classes BGLayer (%d rows): %s", rows, line);
}

// Live watch of BGLayerPlugin's state-like properties: logs only when a value changes, so opening
// Settings shows which value flips. Read-only getters, once a second, on the UI thread.
Obj  g_watch_class = nullptr;
char g_watch_last[1300];
int  g_watch_logs = 0;

bool watch_name(const char* n) {
	if (strstr(n, "Transition") != nullptr || strstr(n, "Gen2") != nullptr) {
		return false; // change with every focused game tile / VR only: noise
	}
	for (const char* key : {"Visible", "Mode", "State", "Active", "Show", "Focus", "Hidden", "Hide", "Enable", "Type", "Kind", "Layer", "Current", "Dim", "Blur", "Mask", "Skip"}) {
		if (strstr(n, key) != nullptr) {
			return true;
		}
	}
	return false;
}

void watch_tick() {
	if (g_watch_class == nullptr || g_plugin == nullptr || g_watch_logs >= 300 || mono_class_get_properties == nullptr) {
		return;
	}
	char   line[1300];
	size_t n    = 0;
	void*  iter = nullptr;
	line[0]     = 0;
	while (Obj p = mono_class_get_properties(g_watch_class, &iter)) {
		const char* name = mono_property_get_name(p);
		Obj         get  = mono_property_get_get_method(p);
		if (name == nullptr || get == nullptr || !watch_name(name)) {
			continue;
		}
		Obj         exc = nullptr;
		Obj         val = mono_runtime_invoke(get, g_plugin, nullptr, &exc);
		const char* txt = "?";
		if (exc != nullptr) {
			txt = "(throws)";
		} else if (val == nullptr) {
			txt = "null";
		} else {
			Obj inner = nullptr;
			Obj str   = mono_object_to_string(val, &inner);
			const char* u = str != nullptr && inner == nullptr ? mono_string_to_utf8(static_cast<char*>(str)) : nullptr;
			txt = u != nullptr ? u : "?";
		}
		const int w = snprintf(line + n, sizeof(line) - n, "%s=%.40s ", name, txt);
		if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
			break;
		}
		n += static_cast<size_t>(w);
	}
	if (strcmp(line, g_watch_last) != 0) {
		memcpy(g_watch_last, line, sizeof(g_watch_last));
		++g_watch_logs;
		wp_log("watch: %s", line);
	}
}

// "Home screen only": BGLayerPlugin.LayerManager_LayerApplicationIdChangedAction runs when the
// foreground layer (home, Settings, library, ...) changes. Its parameters are not known yet, so the
// hook passes up to five integer-register arguments through untouched and logs them.
using LayerChangedFn = void (*)(Obj self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
LayerChangedFn g_layer_changed_orig = nullptr;
int            g_layer_logs         = 0;

void LayerChanged_Hook(Obj self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
	if (g_layer_logs < 200) {
		++g_layer_logs;
		wp_log("layer app changed: a=%#lx b=%#lx c=%#lx (frame %d)", static_cast<unsigned long>(a),
		       static_cast<unsigned long>(b), static_cast<unsigned long>(c), g_boot_frames);
	}
	g_layer_changed_orig(self, a, b, c, d, e);
}

void hook_layer_changes(Obj bg) {
	Obj klass  = mono_class_from_name(bg, "Sce.Vsh.ShellUI.BGLayer", "BGLayerPlugin");
	Obj method = klass != nullptr ? mono_class_get_method_from_name(klass, "LayerManager_LayerApplicationIdChangedAction", -1) : nullptr;
	if (method == nullptr) {
		wp_log("layer hook: method not found");
		return;
	}
	const uint64_t  addr       = reinterpret_cast<uint64_t>(mono_compile_method(method));
	const uintptr_t old_authid = set_ucred_to_ptrace(); // code-page mprotect needs it, as in main()
	const bool      ok         = addr != 0 && InstallDetour(addr, reinterpret_cast<void*>(&LayerChanged_Hook),
	                                                 reinterpret_cast<void**>(&g_layer_changed_orig)) &&
	                g_layer_changed_orig != nullptr;
	if (old_authid != 0) {
		set_proc_authid(getpid(), old_authid);
	}
	wp_log("layer hook: %s (%#lx)", ok ? "installed" : "FAILED", static_cast<unsigned long>(addr));
}

// Scene watch: the BGLayer root's children (class, Visible, ChildrenCount), logged on change.
Obj  g_scene_root = nullptr;
char g_scene_last[1300];
int  g_scene_logs = 0;

bool unbox_bool(Obj o) {
	return o != nullptr && *static_cast<uint8_t*>(mono_object_unbox(o)) != 0;
}

int unbox_int(Obj o) {
	return o != nullptr ? *static_cast<int*>(mono_object_unbox(o)) : -1;
}

void scene_tick() {
	if (g_scene_logs >= 300 || mono_object_get_class == nullptr || mono_class_get_name == nullptr) {
		return;
	}
	if (g_scene_root == nullptr) {
		Obj pui   = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
		Obj scene = pui != nullptr ? mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Scene") : nullptr;
		if (g_ui3_widget == nullptr && pui != nullptr) {
			g_ui3_widget = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Widget");
		}
		g_scene_root = scene != nullptr && g_plugin != nullptr ? property_get(scene, g_plugin, "RootWidget") : nullptr;
		if (g_scene_root == nullptr || g_ui3_widget == nullptr) {
			g_scene_logs = 300;
			wp_log("scene watch: no root");
			return;
		}
		mono_gchandle_new(g_scene_root, 1);
	}
	char   line[1300];
	size_t n = 0;
	line[0]  = 0;
	int count = 0;
	for (Obj w = property_get(g_ui3_widget, g_scene_root, "FirstChild"); w != nullptr && count < 30;
	     w = property_get(g_ui3_widget, w, "NextSibling"), ++count) {
		Obj         k    = mono_object_get_class(w);
		const char* name = k != nullptr ? mono_class_get_name(k) : "?";
		const int   wr   = snprintf(line + n, sizeof(line) - n, "%s:%d/%d ", name, unbox_bool(property_get(g_ui3_widget, w, "Visible")) ? 1 : 0,
		                            unbox_int(property_get(g_ui3_widget, w, "ChildrenCount")));
		if (wr < 0 || n + static_cast<size_t>(wr) >= sizeof(line)) {
			break;
		}
		n += static_cast<size_t>(wr);
	}
	if (strcmp(line, g_scene_last) != 0) {
		memcpy(g_scene_last, line, sizeof(g_scene_last));
		++g_scene_logs;
		wp_log("scene: %s", line);
	}
}

// Layer / app managers elsewhere in ShellUI: list interesting class names, then watch every
// property of singleton-like managers and log changes (opening Settings should flip one).
struct Watched {
	Obj         klass;
	Obj         inst;
	char        name[64];
	char        last[1300];
};
Watched g_watched[8];
int     g_watched_count = 0;
int     g_manager_logs  = 0;

bool name_has(const char* n, std::initializer_list<const char*> keys) {
	for (const char* k : keys) {
		if (strstr(n, k) != nullptr) {
			return true;
		}
	}
	return false;
}

void probe_assembly(const char* dll) {
	if (mono_image_get_table_rows == nullptr || mono_class_get == nullptr || mono_class_get_name == nullptr) {
		return;
	}
	char path[160];
	snprintf(path, sizeof(path), "/system_ex/common_ex/lib/%s.dll", dll);
	Obj image = open_image(path);
	if (image == nullptr) {
		return;
	}
	const int rows = mono_image_get_table_rows(image, 2);
	char      line[1300];
	size_t    n = 0;
	line[0]     = 0;
	for (int i = 2; i <= rows; ++i) {
		Obj         k    = mono_class_get(image, 0x02000000u | static_cast<uint32_t>(i));
		const char* name = k != nullptr ? mono_class_get_name(k) : nullptr;
		if (name == nullptr || name[0] == '<' || !name_has(name, {"Layer", "Focus", "Foreground", "Active", "Scene", "Page", "Screen", "Home", "Setting", "Shell", "AppManager", "Navigation"})) {
			continue;
		}
		const int w = snprintf(line + n, sizeof(line) - n, "%s ", name);
		if (w > 0 && n + static_cast<size_t>(w) < sizeof(line)) {
			n += static_cast<size_t>(w);
		}
		if (g_watched_count < 8 && name_has(name, {"LayerManager", "AppManager", "FocusManager", "ForegroundManager", "SceneManager", "NavigationManager", "ShellAppManager"})) {
			Obj prop = mono_class_get_property_from_name(k, "Instance");
			Obj get  = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
			Obj exc  = nullptr;
			Obj inst = get != nullptr ? mono_runtime_invoke(get, nullptr, nullptr, &exc) : nullptr;
			wp_log("manager %s.%s: Instance %p", dll, name, exc == nullptr ? inst : nullptr);
			Watched& w2 = g_watched[g_watched_count++];
			w2.klass    = k;
			w2.inst     = exc == nullptr ? inst : nullptr; // null: static properties only
			if (w2.inst != nullptr) {
				mono_gchandle_new(w2.inst, 1);
			}
			snprintf(w2.name, sizeof(w2.name), "%s", name);
			w2.last[0] = 0;
		}
	}
	wp_log("classes %s (%d rows): %s", dll, rows, line);
}

void managers_tick() {
	for (int i = 0; i < g_watched_count && g_manager_logs < 400; ++i) {
		Watched& w = g_watched[i];
		if (w.inst == nullptr) {
			continue; // no singleton: instance getters on null would only throw (or worse)
		}
		char     line[1300];
		size_t   n    = 0;
		void*    iter = nullptr;
		line[0]       = 0;
		while (Obj p = mono_class_get_properties(w.klass, &iter)) {
			const char* name = mono_property_get_name(p);
			Obj         get  = mono_property_get_get_method(p);
			if (name == nullptr || get == nullptr || strcmp(name, "Instance") == 0) {
				continue;
			}
			Obj         exc = nullptr;
			Obj         val = mono_runtime_invoke(get, w.inst, nullptr, &exc);
			const char* txt = "?";
			if (exc != nullptr) {
				continue;
			} else if (val == nullptr) {
				txt = "null";
			} else {
				Obj         inner = nullptr;
				Obj         str   = mono_object_to_string(val, &inner);
				const char* u     = str != nullptr && inner == nullptr ? mono_string_to_utf8(static_cast<char*>(str)) : nullptr;
				txt               = u != nullptr ? u : "?";
			}
			const int wr = snprintf(line + n, sizeof(line) - n, "%s=%.40s ", name, txt);
			if (wr < 0 || n + static_cast<size_t>(wr) >= sizeof(line)) {
				break;
			}
			n += static_cast<size_t>(wr);
		}
		if (strcmp(line, w.last) != 0) {
			memcpy(w.last, line, sizeof(w.last));
			++g_manager_logs;
			wp_log("mgr %s: %s", w.name, line);
		}
	}
}

void log_fields(Obj klass, const char* label) {
	if (mono_class_get_fields == nullptr || mono_field_get_name == nullptr) {
		return;
	}
	char   line[1300];
	size_t n    = 0;
	void*  iter = nullptr;
	line[0]     = 0;
	while (Obj f = mono_class_get_fields(klass, &iter)) {
		const char* name = mono_field_get_name(f);
		const int   w    = snprintf(line + n, sizeof(line) - n, "%s ", name != nullptr ? name : "?");
		if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
			break;
		}
		n += static_cast<size_t>(w);
	}
	wp_log("fields %s: %s", label, line);
}

// Where does ShellUI keep "which layer / app is in front"? Full member lists of the candidates.
void probe_focus_classes() {
	struct Target {
		const char* dll;
		const char* name;
	};
	static const Target kTargets[] = {
	    {"Sce.Vsh.ShellUI.AppSystem", "LayerManager"},           {"Sce.Vsh.ShellUI.AppSystem", "ShellAppManager"},
	    {"Sce.Vsh.ShellUI.AppSystem", "FocusLayer"},             {"Sce.Vsh.ShellUI.AppSystem", "ProcessFocusController"},
	    {"Sce.Vsh.ShellUI.AppSystem", "LayerMediator"},          {"Sce.Vsh.ShellUI.ReactNativeShellApp", "SettingsSceneView"},
	};
	for (const Target& t : kTargets) {
		char path[160];
		snprintf(path, sizeof(path), "/system_ex/common_ex/lib/%s.dll", t.dll);
		Obj       image = open_image(path);
		Obj       klass = nullptr;
		const int rows  = image != nullptr && mono_image_get_table_rows != nullptr ? mono_image_get_table_rows(image, 2) : 0;
		for (int i = 2; i <= rows && klass == nullptr; ++i) {
			Obj         k = mono_class_get(image, 0x02000000u | static_cast<uint32_t>(i));
			const char* n = k != nullptr ? mono_class_get_name(k) : nullptr;
			if (n != nullptr && strcmp(n, t.name) == 0) {
				klass = k;
			}
		}
		if (klass == nullptr) {
			wp_log("focus probe: %s not found", t.name);
			continue;
		}
		log_methods(klass, t.name);
		log_properties(klass, t.name);
		log_fields(klass, t.name);
	}
}

void probe_bglayer() {
	probe_focus_classes();
	Obj bg = open_image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.BGLayer.dll");
	if (bg == nullptr) {
		return;
	}
	hook_layer_changes(bg);
	g_watch_class = mono_class_from_name(bg, "Sce.Vsh.ShellUI.BGLayer", "BGLayerPlugin");
	for (const char* name : {"BGLayerPlugin", "BGLayerManager", "BGLayerScene", "BGLayerController", "WallpaperManager", "Wallpaper"}) {
		Obj klass = mono_class_from_name(bg, "Sce.Vsh.ShellUI.BGLayer", name);
		if (klass == nullptr) {
			wp_log("probe: BGLayer.%s not found", name);
			continue;
		}
		log_methods(klass, name);
		void*  iter = nullptr;
		char   line[1300];
		size_t n = 0;
		line[0]  = 0;
		while (Obj p = mono_class_get_properties != nullptr ? mono_class_get_properties(klass, &iter) : nullptr) {
			const int w = snprintf(line + n, sizeof(line) - n, "%s ", mono_property_get_name(p));
			if (w < 0 || n + static_cast<size_t>(w) >= sizeof(line)) {
				break;
			}
			n += static_cast<size_t>(w);
		}
		wp_log("props %s: %s", name, line);
	}
}

bool has_setter(Obj klass, const char* name) {
	Obj prop = mono_class_get_property_from_name(klass, name);
	return prop != nullptr && mono_property_get_set_method(prop) != nullptr;
}

// A pinned, boxed UIColor(0, 0, 0, alpha); returns the unboxed value to pass to a setter.
void* black(float alpha, bool pin = true) {
	float r = 0.0f, g = 0.0f, b = 0.0f;
	Obj   boxed = mono_object_new(g_domain, g_color_class);
	if (boxed == nullptr) {
		return nullptr;
	}
	if (pin) {
		mono_gchandle_new(boxed, 1);
	}
	void* raw     = mono_object_unbox(boxed);
	void* args[4] = {&r, &g, &b, &alpha};
	return invoke(mono_class_get_method_from_name(g_color_class, ".ctor", 4), raw, args, "UIColor()") ? raw : nullptr;
}

bool create_dim_panel() {
	g_dim_tried = true;
	Obj pui = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
	if (pui == nullptr) {
		return false;
	}
	g_ui3_widget      = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Widget");
	g_color_class     = mono_class_from_name(pui, "Sce.PlayStation.PUI", "UIColor");
	Obj scene_class   = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Scene");
	if (g_ui3_widget == nullptr || g_color_class == nullptr || scene_class == nullptr) {
		wp_log("dim: classes widget %p color %p scene %p", g_ui3_widget, g_color_class, scene_class);
		return false;
	}
	log_properties(g_ui3_widget, "UI3.Widget");
	g_dim_root = property_get(scene_class, g_plugin, "RootWidget");
	if (g_dim_root == nullptr) {
		return false;
	}
	mono_gchandle_new(g_dim_root, 1);

	static const char* const kClasses[] = {"Panel", "Rectangle", "ColorRect", "Plane", "Box", "Widget"};
	static const char* const kColors[]  = {"BackgroundColor", "Color", "FillColor", "BaseColor"};
	for (const char* name : kClasses) {
		Obj klass = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", name);
		if (klass == nullptr) {
			wp_log("dim: UI3.%s not found", name);
			continue;
		}
		const char* prop = nullptr;
		for (const char* c : kColors) {
			if (has_setter(klass, c)) {
				prop = c;
				break;
			}
		}
		if (klass != g_ui3_widget) {
			log_properties(klass, name);
		}
		if (prop == nullptr) {
			wp_log("dim: UI3.%s has no colour property", name);
			continue;
		}
		Obj ctor  = mono_class_get_method_from_name(klass, ".ctor", 0);
		Obj panel = ctor != nullptr ? construct_pinned(klass, ctor, nullptr, name) : nullptr;
		if (panel == nullptr) {
			wp_log("dim: UI3.%s cannot be created", name);
			continue;
		}
		float zero = 0.0f, width = 1920.0f, height = 1080.0f;
		property_set(g_ui3_widget, panel, "X", &zero);
		property_set(g_ui3_widget, panel, "Y", &zero);
		property_set(g_ui3_widget, panel, "Width", &width);
		property_set(g_ui3_widget, panel, "Height", &height);
		if (has_setter(klass, "BackgroundVisibility")) {
			bool on = true;
			property_set(klass, panel, "BackgroundVisibility", &on);
		}
		void* color = black(0.0f);
		if (color == nullptr || !property_set(klass, panel, prop, color)) {
			wp_log("dim: UI3.%s.%s cannot be set", name, prop);
			continue;
		}
		void* child[1] = {panel};
		if (!invoke(find_method_up(g_ui3_widget, "AppendChild", 1), g_dim_root, child, "AppendChild(dim)")) {
			continue;
		}
		g_dim_panel = panel;
		g_dim_class = klass;
		g_dim_prop  = prop;
		wp_log("dim: using UI3.%s.%s", name, prop);
		return true;
	}
	wp_log("dim: no usable UI3 class, dim unavailable");
	return false;
}

// Keep the panel above the video: a (re)started video view is appended after it.
void raise_dim() {
	if (g_dim_panel == nullptr) {
		return;
	}
	void* child[1] = {g_dim_panel};
	invoke(find_method_up(g_ui3_widget, "RemoveChild", 1), g_dim_root, child, "RemoveChild(dim)");
	invoke(find_method_up(g_ui3_widget, "AppendChild", 1), g_dim_root, child, "AppendChild(dim)");
}

// Dim only while our video plays; Sony's own wallpaper is left alone.
void refresh_dim() {
	if (g_black_now > 0.0f) {
		return; // the game-launch fade owns the panel colour
	}
	int want = video_active() ? g_dim_req.load() : 0;
	if (want == 0 && g_blur_target != nullptr && g_blur_target == g_dim_panel) {
		want = 3; // faint tint: the blur effect needs a panel that draws something
	}
	if (want < 0 || want == g_dim_shown) {
		return;
	}
	if (g_dim_panel == nullptr) {
		if (want == 0 || g_dim_tried || !create_dim_panel()) {
			return;
		}
	}
	void* color = black(static_cast<float>(want) / 100.0f);
	if (color != nullptr && property_set(g_dim_class, g_dim_panel, g_dim_prop, color)) {
		g_dim_shown = want;
		wp_log("dim: %d%%", want);
	}
}

// ---- looks: bottom fade, top fade, vignette, haze ---------------------------------------------
// Built from plain UI3 Panels (the class dim proved), as children of the dim panel so they stay
// above the video after a switch and fade out with it in Settings. A gradient = many thin bands.

constexpr const char* kLooksFile = "/system_tmp/liveshell/looks.txt";
enum Look { kBottom = 0, kTop = 1, kVignette = 2, kHaze = 3, kLooks = 4 };
std::atomic<int> g_look_req[kLooks];
int              g_look_shown[kLooks] = {-1, -1, -1, -1};
Obj              g_look_panels[kLooks][40];
float            g_look_weight[kLooks][40];
int              g_look_count[kLooks] = {};
bool             g_look_built[kLooks] = {};

void* tint(float r, float g, float b, float a) {
	Obj boxed = mono_object_new(g_domain, g_color_class);
	if (boxed == nullptr) {
		return nullptr;
	}
	mono_gchandle_new(boxed, 1);
	void* raw     = mono_object_unbox(boxed);
	void* args[4] = {&r, &g, &b, &a};
	return invoke(mono_class_get_method_from_name(g_color_class, ".ctor", 4), raw, args, "UIColor()") ? raw : nullptr;
}

bool add_band(Look look, float x, float y, float w, float h, float weight) {
	if (g_look_count[look] >= 40) {
		return false;
	}
	Obj ctor  = mono_class_get_method_from_name(g_dim_class, ".ctor", 0);
	Obj panel = ctor != nullptr ? construct_pinned(g_dim_class, ctor, nullptr, "look band") : nullptr;
	if (panel == nullptr) {
		return false;
	}
	property_set(g_ui3_widget, panel, "X", &x);
	property_set(g_ui3_widget, panel, "Y", &y);
	property_set(g_ui3_widget, panel, "Width", &w);
	property_set(g_ui3_widget, panel, "Height", &h);
	if (has_setter(g_dim_class, "BackgroundVisibility")) {
		bool on = true;
		property_set(g_dim_class, panel, "BackgroundVisibility", &on);
	}
	void* clear = tint(0.0f, 0.0f, 0.0f, 0.0f);
	if (clear != nullptr) {
		property_set(g_dim_class, panel, g_dim_prop, clear);
	}
	void* child[1] = {panel};
	if (!invoke(find_method_up(g_ui3_widget, "AppendChild", 1), g_dim_panel, child, "AppendChild(look)")) {
		return false;
	}
	g_look_panels[look][g_look_count[look]] = panel;
	g_look_weight[look][g_look_count[look]] = weight;
	++g_look_count[look];
	return true;
}

float smooth(float t) {
	return t * t * (3.0f - 2.0f * t);
}

void build_look(Look look) {
	g_look_built[look] = true;
	const float W = 1920.0f, H = 1080.0f;
	if (look == kBottom || look == kTop) {
		// 16 bands over the bottom 45 % / top 30 %, darker towards the edge.
		const int   n     = 16;
		const float span  = look == kBottom ? H * 0.45f : H * 0.30f;
		const float band  = span / n;
		for (int i = 0; i < n; ++i) {
			const float edge = smooth(static_cast<float>(i + 1) / n); // 0 inside .. 1 at the edge
			const float y    = look == kBottom ? H - span + i * band : (n - 1 - i) * band;
			add_band(look, 0.0f, y, W, band + 1.0f, edge);
		}
	} else if (look == kVignette) {
		// 10 rings of edge strips (no overlap at the corners), darkest at the screen edge.
		const int   rings = 10;
		const float tx = 34.0f, ty = 20.0f;
		for (int i = 0; i < rings; ++i) {
			const float k  = 1.0f - static_cast<float>(i) / rings;
			const float wt = k * k;
			const float x0 = i * tx, y0 = i * ty;
			add_band(look, x0, y0, W - 2 * x0, ty, wt);                       // top
			add_band(look, x0, H - y0 - ty, W - 2 * x0, ty, wt);              // bottom
			add_band(look, x0, y0 + ty, tx, H - 2 * (y0 + ty), wt);           // left
			add_band(look, W - x0 - tx, y0 + ty, tx, H - 2 * (y0 + ty), wt);  // right
		}
	} else {
		add_band(look, 0.0f, 0.0f, W, H, 1.0f); // haze: one white veil
	}
	wp_log("look %d: %d panels", static_cast<int>(look), g_look_count[look]);
}

void refresh_looks() {
	if (g_dim_panel == nullptr) {
		if (g_dim_tried || !video_active()) {
			return;
		}
		create_dim_panel();
		if (g_dim_panel == nullptr) {
			return;
		}
	}
	for (int l = 0; l < kLooks; ++l) {
		const int want = video_active() ? g_look_req[l].load() : 0;
		if (want < 0 || want == g_look_shown[l]) {
			continue;
		}
		if (want > 0 && !g_look_built[l]) {
			build_look(static_cast<Look>(l));
		}
		g_look_shown[l] = want;
		// Strength per level: Light / Strong.
		const float max_a = l == kHaze ? (want >= 2 ? 0.35f : 0.18f)
		                  : l == kVignette ? (want >= 2 ? 0.85f : 0.55f)
		                                   : (want >= 2 ? 0.85f : 0.55f);
		const float c = l == kHaze ? 1.0f : 0.0f;
		for (int i = 0; i < g_look_count[l]; ++i) {
			void* col = tint(c, c, c, want > 0 ? max_a * g_look_weight[l][i] : 0.0f);
			if (col != nullptr) {
				property_set(g_dim_class, g_look_panels[l][i], g_dim_prop, col);
			}
		}
		wp_log("look %d: level %d", l, want);
	}
}

// ---- blur: a post effect on the video view ---------------------------------------------------
// UI3.Widget has a PostEffect property; its type and the blur classes are not known yet, so the
// first use logs them and tries: an enum value named *Blur*, or a *Blur* class instance.

constexpr const char* kBlurFile = "/system_tmp/liveshell/blur.txt";
std::atomic<int> g_blur_req{-1};
int              g_blur_shown   = -1;
Obj              g_blur_view    = nullptr;
bool             g_blur_probed  = false;
bool             g_blur_broken  = false;
Obj              g_pe_type      = nullptr;
bool             g_pe_enum      = false;
Obj              g_blur_classes[8];
int              g_blur_count   = 0;

const char* type_of_getter(Obj klass, const char* prop_name) {
	Obj prop = mono_class_get_property_from_name(klass, prop_name);
	Obj get  = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
	if (get == nullptr || mono_method_signature == nullptr || mono_signature_get_return_type == nullptr || mono_type_get_name == nullptr) {
		return nullptr;
	}
	Obj t = mono_signature_get_return_type(mono_method_signature(get));
	return t != nullptr ? mono_type_get_name(t) : nullptr;
}

void hook_blur_effect(Obj k);

void probe_blur() {
	g_blur_probed = true;
	Obj pui       = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
	if (pui == nullptr) {
		return;
	}
	if (g_ui3_widget == nullptr) {
		g_ui3_widget = mono_class_from_name(pui, "Sce.PlayStation.PUI.UI3", "Widget");
	}
	Obj prop = g_ui3_widget != nullptr ? mono_class_get_property_from_name(g_ui3_widget, "PostEffect") : nullptr;
	Obj get  = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
	if (get != nullptr && mono_method_signature != nullptr && mono_signature_get_return_type != nullptr) {
		Obj         t  = mono_signature_get_return_type(mono_method_signature(get));
		const char* tn = t != nullptr && mono_type_get_name != nullptr ? mono_type_get_name(t) : nullptr;
		g_pe_type      = t != nullptr && mono_class_from_mono_type != nullptr ? mono_class_from_mono_type(t) : nullptr;
		g_pe_enum      = g_pe_type != nullptr && mono_class_is_enum != nullptr && mono_class_is_enum(g_pe_type) != 0;
		wp_log("blur: Widget.PostEffect is %s (enum %d, setter %d)", tn != nullptr ? tn : "?", g_pe_enum ? 1 : 0,
		       has_setter(g_ui3_widget, "PostEffect") ? 1 : 0);
		if (g_pe_type != nullptr) {
			log_fields(g_pe_type, "PostEffect type");
			log_properties(g_pe_type, "PostEffect type");
			log_methods(g_pe_type, "PostEffect type");
		}
	} else {
		wp_log("blur: no Widget.PostEffect getter");
	}
	if (mono_image_get_table_rows == nullptr) {
		return;
	}
	const int rows = mono_image_get_table_rows(pui, 2);
	char      line[1300];
	size_t    n = 0;
	line[0]     = 0;
	for (int i = 2; i <= rows; ++i) {
		Obj         k    = mono_class_get(pui, 0x02000000u | static_cast<uint32_t>(i));
		const char* name = k != nullptr ? mono_class_get_name(k) : nullptr;
		if (name == nullptr || name[0] == '<' || !name_has(name, {"Blur", "PostEffect", "Effect"})) {
			continue;
		}
		const int w = snprintf(line + n, sizeof(line) - n, "%s ", name);
		if (w > 0 && n + static_cast<size_t>(w) < sizeof(line)) {
			n += static_cast<size_t>(w);
		}
		if (strstr(name, "Blur") != nullptr && g_blur_count < 8) {
			g_blur_classes[g_blur_count++] = k;
			log_properties(k, name);
			log_methods(k, name);
		}
	}
	wp_log("blur: PUI effect classes: %s", line);
}

// Blur research: does BackgroundBlurEffect ever Bind / Render, and on which widget? Pass-through
// detours (integer-register arguments only, untouched).
using Fx5 = void (*)(Obj self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e);
Fx5 g_fx_bind_orig   = nullptr;
Fx5 g_fx_render_orig = nullptr;
int g_fx_binds       = 0;
long g_fx_renders    = 0;

void FxBind_Hook(Obj self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
	if (++g_fx_binds <= 40) {
		wp_log("blurfx Bind #%d: effect %p arg %#lx%s", g_fx_binds, self, static_cast<unsigned long>(a),
		       reinterpret_cast<Obj>(a) == g_dim_panel ? " (our dim panel)" : "");
	}
	g_fx_bind_orig(self, a, b, c, d, e);
}

void FxRender_Hook(Obj self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
	++g_fx_renders;
	if (g_fx_renders == 1 || g_fx_renders % 600 == 0) {
		wp_log("blurfx Render calls: %ld (effect %p)", g_fx_renders, self);
	}
	g_fx_render_orig(self, a, b, c, d, e);
}

void hook_blur_effect(Obj k) {
	const uintptr_t old_authid = set_ucred_to_ptrace();
	for (int i = 0; i < 2; ++i) {
		const char* name = i == 0 ? "Bind" : "Render";
		Obj         m    = mono_class_get_method_from_name(k, name, -1);
		const uint64_t addr = m != nullptr ? reinterpret_cast<uint64_t>(mono_compile_method(m)) : 0;
		const bool ok = addr != 0 && InstallDetour(addr, reinterpret_cast<void*>(i == 0 ? &FxBind_Hook : &FxRender_Hook),
		                                           reinterpret_cast<void**>(i == 0 ? &g_fx_bind_orig : &g_fx_render_orig));
		wp_log("blurfx hook %s: %s", name, ok ? "installed" : "FAILED");
	}
	if (old_authid != 0) {
		set_proc_authid(getpid(), old_authid);
	}
}

// Sets a numeric property whatever its type (float / double / int).
void set_number(Obj klass, Obj obj, const char* name, double value) {
	const char* t = type_of_getter(klass, name);
	if (t == nullptr || !has_setter(klass, name)) {
		return;
	}
	if (strcmp(t, "System.Single") == 0) {
		float f = static_cast<float>(value);
		property_set(klass, obj, name, &f);
	} else if (strcmp(t, "System.Double") == 0) {
		double d = value;
		property_set(klass, obj, name, &d);
	} else if (strcmp(t, "System.Int32") == 0 || strcmp(t, "System.UInt32") == 0) {
		int v = static_cast<int>(value);
		property_set(klass, obj, name, &v);
	} else {
		return;
	}
	wp_log("blur: %s = %g (%s)", name, value, t);
}

// g_blur_target (declared with the dim globals): widget that carries the effect.

void clear_blur(Obj target) {
	if (target != nullptr) {
		property_set(g_ui3_widget, target, "PostEffect", nullptr);
	}
}

// Only UI3 effects (subclasses of UI3.PostEffect): UI2.BlurEffect threw on attach and the
// half-attached effect crashed ShellUI ~20 s later (test 16). BackgroundBlurEffect is a "frosted
// glass" effect: it goes on the panel IN FRONT of the video and blurs what is behind it.
bool attach_blur(Obj view, int level) {
	Obj fx_class = nullptr;
	for (int i = 0; i < g_blur_count && fx_class == nullptr; ++i) {
		Obj k = g_blur_classes[i];
		if (mono_class_get_parent(k) == g_pe_type && strcmp(mono_class_get_name(k), "BackgroundBlurEffect") == 0) {
			fx_class = k;
		}
	}
	for (int i = 0; i < g_blur_count && fx_class == nullptr; ++i) {
		if (mono_class_get_parent(g_blur_classes[i]) == g_pe_type) {
			fx_class = g_blur_classes[i];
		}
	}
	if (fx_class == nullptr) {
		wp_log("blur: no UI3 blur effect class");
		return false;
	}
	if (g_dim_panel == nullptr && !g_dim_tried) {
		create_dim_panel(); // the frosted-glass layer; its colour stays whatever dim says
	}
	const char* fx_name = mono_class_get_name(fx_class);
	Obj         ctor    = mono_class_get_method_from_name(fx_class, ".ctor", 0);
	for (Obj target : {g_dim_panel, view}) {
		if (target == nullptr) {
			continue;
		}
		Obj fx = ctor != nullptr ? construct_pinned(fx_class, ctor, nullptr, fx_name) : nullptr;
		if (fx == nullptr) {
			wp_log("blur: %s cannot be created", fx_name);
			return false;
		}
		set_number(fx_class, fx, "Radius", level >= 2 ? 24.0 : 10.0);
		bool enabled = true;
		if (has_setter(fx_class, "Enabled")) {
			property_set(fx_class, fx, "Enabled", &enabled);
		}
		if (property_set(g_ui3_widget, target, "PostEffect", fx)) {
			g_blur_target = target;
			if (target == g_dim_panel && g_dim_shown <= 0) {
				// A fully transparent panel draws nothing, so the effect had nothing to run on
				// (test 17): give it a faint tint while blur is on.
				void* faint = black(0.03f);
				if (faint != nullptr && property_set(g_dim_class, g_dim_panel, g_dim_prop, faint)) {
					g_dim_shown = 3;
				}
			}
			Obj r = property_get(g_ui3_widget, target, "RenderingInPostEffect");
			wp_log("blur: target RenderingInPostEffect=%d", r != nullptr && *static_cast<uint8_t*>(mono_object_unbox(r)) != 0 ? 1 : 0);
			wp_log("blur: %s on the %s", fx_name, target == g_dim_panel ? "dim panel" : "video view");
			return true;
		}
		clear_blur(target); // never leave a half-attached effect behind
		wp_log("blur: %s refused by the %s, removed again", fx_name, target == g_dim_panel ? "dim panel" : "video view");
	}
	return false;
}

void refresh_blur() {
	Obj       view = g_own_view != nullptr ? g_own_view : g_boot_player;
	const int want = view != nullptr ? g_blur_req.load() : 0;
	if (g_blur_broken || want < 0 || (want == g_blur_shown && (view == g_blur_view || g_blur_target == g_dim_panel))) {
		return;
	}
	g_blur_shown = want;
	g_blur_view  = view;
	if (!g_blur_probed && want > 0) {
		probe_blur();
	}
	clear_blur(g_blur_target);
	g_blur_target = nullptr;
	g_dim_shown   = -1; // refresh_dim puts the real dim colour back (the faint blur tint goes)
	if (want == 0) {
		wp_log("blur: off");
		return;
	}
	if (view != nullptr && !attach_blur(view, want)) {
		g_blur_broken = true;
		wp_log("blur: nothing worked, blur unavailable this session");
	}
}

// ---- "In menus: hide" -------------------------------------------------------------------------
// LayerManager.s_curFocusLayer (static, enum FocusLayer { None, Game, TopMenu, ShellApp }) says
// which layer has focus. ShellApp = Settings and the other system apps: hide our video (and the
// dim panel) there so the stock background shows; home (TopMenu) shows it again.

constexpr const char* kMenusFile = "/system_tmp/liveshell/menus.txt";
std::atomic<int> g_menus_req{0}; // 0 show in menus, 1 hide in menus
Obj  g_focus_field  = nullptr;
Obj  g_focus_vtable = nullptr;
int  g_shellapp_val = -1;
int  g_game_val     = -1;
int  g_focus_now    = -1;
bool g_focus_ready  = false;
bool g_focus_failed = false;
bool g_hidden       = false;
Obj  g_hidden_view  = nullptr;
int  g_hide_changed = 0;
float g_opacity     = -1.0f;
float g_view_op     = -1.0f; // video opacity actually set
float g_view_in     = 1.0f;  // a new video's own fade-in, 0..1
bool  g_was_game    = false;
bool  g_hold_black  = false; // back from a game, video not restarted yet: our panel stays black
int   g_hold_start  = 0;
int   g_hold_view_tick = -1;

Obj find_class(const char* dll, const char* name) {
	char path[160];
	snprintf(path, sizeof(path), "/system_ex/common_ex/lib/%s.dll", dll);
	Obj       image = open_image(path);
	const int rows  = image != nullptr && mono_image_get_table_rows != nullptr ? mono_image_get_table_rows(image, 2) : 0;
	for (int i = 2; i <= rows; ++i) {
		Obj         k = mono_class_get(image, 0x02000000u | static_cast<uint32_t>(i));
		const char* n = k != nullptr ? mono_class_get_name(k) : nullptr;
		if (n != nullptr && strcmp(n, name) == 0) {
			return k;
		}
	}
	return nullptr;
}

void setup_focus() {
	g_focus_ready = true;
	Obj lm        = find_class("Sce.Vsh.ShellUI.AppSystem", "LayerManager");
	Obj fl        = find_class("Sce.Vsh.ShellUI.AppSystem", "FocusLayer");
	g_focus_field = lm != nullptr ? mono_class_get_field_from_name(lm, "s_curFocusLayer") : nullptr;
	g_focus_vtable = lm != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, lm) : nullptr;
	Obj fl_vt     = fl != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, fl) : nullptr;
	Obj sa        = fl != nullptr ? mono_class_get_field_from_name(fl, "ShellApp") : nullptr;
	if (sa != nullptr && fl_vt != nullptr && mono_field_static_get_value != nullptr) {
		mono_field_static_get_value(fl_vt, sa, &g_shellapp_val);
		Obj gf = mono_class_get_field_from_name(fl, "Game");
		if (gf != nullptr) {
			mono_field_static_get_value(fl_vt, gf, &g_game_val);
		}
	}
	g_focus_failed = g_focus_field == nullptr || g_focus_vtable == nullptr || g_shellapp_val < 0;
	wp_log("focus: LayerManager %p field %p vtable %p, ShellApp = %d%s", lm, g_focus_field, g_focus_vtable, g_shellapp_val,
	       g_focus_failed ? " -> hide in menus unavailable" : "");
}

void set_visible(Obj w, bool on) {
	if (w != nullptr && g_ui3_widget != nullptr) {
		property_set(g_ui3_widget, w, "Visible", &on);
	}
}

// How does Sony get a working glass blur? Walk ShellUI's whole widget tree (from
// LayerManager.s_root_scene) and log every widget that has a PostEffect, with its setup.
int g_scan_at    = -1;
int g_scans_done = 0;

void scan_widget(Obj w, int depth, int& visited, int& found, const char* path) {
	for (; w != nullptr && visited < 8000 && found < 40; w = property_get(g_ui3_widget, w, "NextSibling")) {
		++visited;
		Obj         k    = mono_object_get_class(w);
		const char* name = k != nullptr ? mono_class_get_name(k) : "?";
		char        here[200];
		snprintf(here, sizeof(here), "%s/%s", depth < 6 ? path : "...", name);
		Obj fx = property_get(g_ui3_widget, w, "PostEffect");
		if (fx != nullptr) {
			++found;
			Obj         fk   = mono_object_get_class(fx);
			Obj         rip  = property_get(g_ui3_widget, w, "RenderingInPostEffect");
			Obj         rg   = property_get(g_ui3_widget, w, "RenderGroup");
			Obj         rk   = rg != nullptr ? mono_object_get_class(rg) : nullptr;
			Obj         wd   = property_get(g_ui3_widget, w, "Width");
			Obj         ht   = property_get(g_ui3_widget, w, "Height");
			wp_log("effect #%d depth %d: %s fx=%s rendering=%d renderGroup=%s size=%gx%g", found, depth, here,
			       fk != nullptr ? mono_class_get_name(fk) : "?", unbox_bool(rip) ? 1 : 0,
			       rk != nullptr ? mono_class_get_name(rk) : "null",
			       wd != nullptr ? *static_cast<float*>(mono_object_unbox(wd)) : -1.0f,
			       ht != nullptr ? *static_cast<float*>(mono_object_unbox(ht)) : -1.0f);
			if (fk != nullptr && found <= 3) {
				log_properties(fk, mono_class_get_name(fk));
			}
		}
		Obj child = property_get(g_ui3_widget, w, "FirstChild");
		if (child != nullptr && depth < 60) {
			scan_widget(child, depth + 1, visited, found, here);
		}
	}
}

void scan_effects() {
	++g_scans_done;
	Obj lm    = find_class("Sce.Vsh.ShellUI.AppSystem", "LayerManager");
	Obj field = lm != nullptr ? mono_class_get_field_from_name(lm, "s_root_scene") : nullptr;
	Obj vt    = lm != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, lm) : nullptr;
	Obj scene = nullptr;
	if (field != nullptr && vt != nullptr) {
		mono_field_static_get_value(vt, field, &scene);
	}
	Obj sk   = scene != nullptr ? mono_object_get_class(scene) : nullptr;
	Obj root = sk != nullptr ? property_get(sk, scene, "RootWidget") : nullptr;
	wp_log("effect scan %d: root scene %p (%s), root widget %p", g_scans_done, scene, sk != nullptr ? mono_class_get_name(sk) : "?", root);
	if (root == nullptr) {
		return;
	}
	int visited = 0, found = 0;
	scan_widget(root, 0, visited, found, "");
	wp_log("effect scan %d: %d widgets, %d with a PostEffect", g_scans_done, visited, found);
}

// LayerManager.s_logFocusApplicationName: the focused app's name, read when focus changes.
Obj  g_appname_field = nullptr;
bool g_is_settings   = false;
float g_fade         = 0.0f; // 0 = video fully shown, 1 = fully hidden

void read_focus_app(char* out, size_t size) {
	out[0] = 0;
	if (g_appname_field == nullptr) {
		Obj lm          = find_class("Sce.Vsh.ShellUI.AppSystem", "LayerManager");
		g_appname_field = lm != nullptr ? mono_class_get_field_from_name(lm, "s_logFocusApplicationName") : nullptr;
	}
	Obj str = nullptr;
	if (g_appname_field != nullptr) {
		mono_field_static_get_value(g_focus_vtable, g_appname_field, &str);
	}
	const char* u = str != nullptr ? mono_string_to_utf8(static_cast<char*>(str)) : nullptr;
	snprintf(out, size, "%s", u != nullptr ? u : "");
}

// Which system app is in front: ShellAppManager.s_focusLayerAppId, LayerManager.s_lastFocusedApplicationId
// and ShellAppManager.GetLastShellAppTitleId(). Logged to tell Settings from Search etc.
int g_ids_at = -1;

void log_focus_ids(const char* when) {
	static Obj sam = nullptr, sam_vt = nullptr, f_app = nullptr, f_last = nullptr, m_title = nullptr;
	static bool ready = false;
	if (!ready) {
		ready  = true;
		sam    = find_class("Sce.Vsh.ShellUI.AppSystem", "ShellAppManager");
		sam_vt = sam != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, sam) : nullptr;
		f_app  = sam != nullptr ? mono_class_get_field_from_name(sam, "s_focusLayerAppId") : nullptr;
		Obj lm = find_class("Sce.Vsh.ShellUI.AppSystem", "LayerManager");
		f_last = lm != nullptr ? mono_class_get_field_from_name(lm, "s_lastFocusedApplicationId") : nullptr;
		m_title = sam != nullptr ? mono_class_get_method_from_name(sam, "GetLastShellAppTitleId", 0) : nullptr;
	}
	int app_id = -1, last_id = -1;
	if (f_app != nullptr && sam_vt != nullptr) {
		mono_field_static_get_value(sam_vt, f_app, &app_id);
	}
	if (f_last != nullptr) {
		mono_field_static_get_value(g_focus_vtable, f_last, &last_id);
	}
	const char* title = nullptr;
	if (m_title != nullptr) {
		Obj exc = nullptr;
		Obj str = mono_runtime_invoke(m_title, nullptr, nullptr, &exc);
		title   = exc == nullptr && str != nullptr ? mono_string_to_utf8(static_cast<char*>(str)) : nullptr;
	}
	wp_log("focus ids (%s): shellapp id %#x, last focused app %#x, last shell app title '%s'", when,
	       static_cast<unsigned>(app_id), static_cast<unsigned>(last_id), title != nullptr ? title : "?");
}

bool contains_nocase(const char* hay, const char* needle) {
	for (const char* h = hay; *h != 0; ++h) {
		size_t i = 0;
		while (needle[i] != 0 && h[i] != 0 && tolower(static_cast<unsigned char>(h[i])) == tolower(static_cast<unsigned char>(needle[i]))) {
			++i;
		}
		if (needle[i] == 0) {
			return true;
		}
	}
	return false;
}

// VideoView.BlendMode: 3 = overwrite (what we use, opaque). The "normal" value is read from the
// enum (Normal / Half / Alpha / Blend), logged once.
int  g_blend_normal = -2;

void set_blend(Obj view, bool overwrite) {
	if (g_videoview_class == nullptr) {
		return;
	}
	if (g_blend_normal == -2) {
		g_blend_normal = -1;
		Obj prop = mono_class_get_property_from_name(g_videoview_class, "BlendMode");
		Obj get  = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
		Obj t    = get != nullptr && mono_method_signature != nullptr ? mono_signature_get_return_type(mono_method_signature(get)) : nullptr;
		Obj ek   = t != nullptr && mono_class_from_mono_type != nullptr ? mono_class_from_mono_type(t) : nullptr;
		Obj vt   = ek != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, ek) : nullptr;
		if (ek != nullptr) {
			log_fields(ek, "BlendMode");
		}
		for (const char* n : {"Normal", "Half", "Alpha", "Blend", "AlphaBlend"}) {
			Obj f = ek != nullptr && vt != nullptr ? mono_class_get_field_from_name(ek, n) : nullptr;
			if (f != nullptr) {
				int v = 0; // byte-sized enum: only the low byte is written
				mono_field_static_get_value(vt, f, &v);
				v &= 0xFF;
				g_blend_normal = v;
				wp_log("blend: normal = %s (%d)", n, v);
				break;
			}
		}
	}
	if (g_blend_normal < 0) {
		return;
	}
	uint8_t mode = overwrite ? 3 : static_cast<uint8_t>(g_blend_normal);
	property_set(g_videoview_class, view, "BlendMode", &mode);
}

void focus_tick() {
	if (!g_focus_ready) {
		setup_focus();
	}
	// No focus info: never hide, but still run the fade below (new videos start at opacity 0).
	int focus = -2;
	if (!g_focus_failed) {
		mono_field_static_get_value(g_focus_vtable, g_focus_field, &focus);
	}
	if (focus != g_focus_now && !g_focus_failed) {
		g_focus_now = focus;
		char app[128];
		read_focus_app(app, sizeof(app));
		// The name is "ReactNativePlugin" for Settings, Search and the rest alike (test 20), so for
		// now every system app counts; the ids below tell Settings apart for the next build.
		g_is_settings = focus == g_shellapp_val;
		wp_log("focus layer: %d, app '%s'", focus, app);
		if (false) { // effect scan: research only
			g_scan_at = g_tick + 60; // once the screen is drawn
		}
	}
	if (g_scan_at >= 0 && g_tick >= g_scan_at) {
		g_scan_at = -1;
		scan_effects();
	}
	if (g_ids_at >= 0 && g_tick >= g_ids_at) {
		g_ids_at = -1;
		log_focus_ids("+0.5 s");
	}
	// Two reasons to fade our layers out:
	//  - a game / app is being started (focus Game): at once, quick (~0.5 s). Sony's "can't run this
	//    app" dialog was hidden under our layers while the game pause had not kicked in yet (test 24).
	//  - Settings with "Hide in Settings" on: focus flips before Settings is drawn, so a short wait,
	//    then a slow eased fade (~1 s). Back home: eased fade in (~0.7 s).
	Obj        view    = g_own_view != nullptr ? g_own_view : g_boot_player;
	const bool game    = g_game_val >= 0 && focus == g_game_val;
	const bool hide    = game || (g_menus_req.load() == 1 && g_is_settings && view != nullptr);
	if (hide != g_hidden) {
		g_hidden       = hide;
		g_hide_changed = g_tick;
		wp_log("layers %s (%s)", hide ? "fading out" : "fading in", game ? "game" : hide ? "settings" : "home");
	}
	if (view != g_hidden_view) {
		g_hidden_view = view;
		g_opacity     = -1.0f; // new view: apply again
		g_view_op     = -1.0f;
		// A freshly started video (boot, switch, back from a game) fades in on its own instead of
		// popping in at full strength (test 28: after "Closing..." it appeared at once).
		g_view_in = view != nullptr ? 0.0f : 1.0f;
		if (view != nullptr && g_hold_black && g_hold_view_tick < 0) {
			g_hold_view_tick = g_tick; // the video is back: cross-fade black -> video
		}
	}
	// Back from a game while "Pause while a game runs" has the video stopped: Sony's background
	// showed until the video restarted (test 29). Hold black instead until the video is back
	// (max ~5 s), then cross-fade into it (or, with no video coming, into Sony's background).
	if (game) {
		g_was_game = true;
	} else if (g_was_game) {
		g_was_game = false;
		if (view == nullptr) {
			g_hold_black     = true;
			g_hold_start     = g_tick;
			g_hold_view_tick = -1;
			if (g_dim_panel == nullptr && !g_dim_tried) {
				create_dim_panel();
			}
		}
	}
	// Starting a game: fade to black (~0.35 s), hold black (~1.5 s) while the game starts, then
	// let go (an error dialog becomes readable then; test 25).
	// Starting a game: no black any more (user, test 30): our layers fade out slowly (below) and
	// the game's own launch background shows through.
	float to_black = 0.0f;
	if (g_hold_black && !(hide && game)) {
		if (g_hold_view_tick < 0 && g_tick - g_hold_start > 300) {
			g_hold_view_tick = g_tick; // no video came: let Sony's background show after all
		}
		if (g_hold_view_tick < 0) {
			to_black = 1.0f;
		} else {
			const int t = g_tick - g_hold_view_tick;
			if (t >= 30) {
				g_hold_black = false;
			} else {
				const float k = static_cast<float>(t) / 30.0f;
				to_black      = 1.0f - k * k * (3.0f - 2.0f * k);
			}
		}
	}
	if (to_black != g_black_now && g_dim_panel != nullptr && g_dim_class != nullptr) {
		g_black_now   = to_black;
		const float d = video_active() ? static_cast<float>(g_dim_req.load() < 0 ? 0 : g_dim_req.load()) / 100.0f : 0.0f;
		void*       c = black(d + (1.0f - d) * to_black, false);
		if (c != nullptr) {
			property_set(g_dim_class, g_dim_panel, g_dim_prop, c);
		}
		g_dim_shown = to_black > 0.0f ? -2 : -1; // refresh_dim puts the real dim back afterwards
	}
	if (hide) {
		if (game) {
			g_fade = g_fade + 1.0f / 72.0f > 1.0f ? 1.0f : g_fade + 1.0f / 72.0f; // ~1.2 s, at once
		} else if (g_tick - g_hide_changed >= 9) {
			g_fade = g_fade + 1.0f / 60.0f > 1.0f ? 1.0f : g_fade + 1.0f / 60.0f;
		}
	} else {
		g_fade = g_fade - 1.0f / 24.0f < 0.0f ? 0.0f : g_fade - 1.0f / 24.0f;
	}
	g_view_in = g_view_in + 1.0f / 30.0f > 1.0f ? 1.0f : g_view_in + 1.0f / 30.0f;
	// Going out: ease-in-out (slow start, slow end). Coming back home: ease-out, i.e. our layers
	// cover Sony's background almost at once and then settle (test 26).
	float next;
	if (hide) {
		const float eased = g_fade < 0.5f ? 4.0f * g_fade * g_fade * g_fade
		                                  : 1.0f - (-2.0f * g_fade + 2.0f) * (-2.0f * g_fade + 2.0f) * (-2.0f * g_fade + 2.0f) / 2.0f;
		next = 1.0f - eased;
	} else {
		next = 1.0f - g_fade * g_fade * g_fade;
	}
	const float vi      = 1.0f - (1.0f - g_view_in) * (1.0f - g_view_in) * (1.0f - g_view_in); // ease-out
	float       view_op = next * vi;
	if (view != nullptr && view_op != g_view_op) {
		const bool was_full = g_view_op >= 1.0f || g_view_op < 0.0f;
		g_view_op           = view_op;
		// "Overwrite" blending replaces what is behind the video, so Sony's background stayed
		// invisible until the end of a fade and then popped in (test 24). Blend normally while
		// fading, overwrite again once fully shown.
		if (view_op < 1.0f && was_full) {
			set_blend(view, false);
		} else if (view_op >= 1.0f) {
			set_blend(view, true);
		}
		property_set(g_ui3_widget, view, "Opacity", &view_op);
	}
	if (next != g_opacity) {
		g_opacity = next;
		if (g_dim_panel != nullptr) {
			property_set(g_ui3_widget, g_dim_panel, "Opacity", &next);
		}
	}
}

// ---- parallax --------------------------------------------------------------------------------
// When the home screen moves between game tiles, BGLayerPlugin.TransitionType briefly becomes
// CustomImageSlideInLeft / Right. The video (drawn a bit larger so no edge shows) then shifts a
// few pixels that way and eases back: a depth effect. One property write per frame while moving.

constexpr const char* kParallaxFile = "/system_tmp/liveshell/parallax.txt";
constexpr float       kOverX = 36.0f, kOverY = 20.0f; // extra size on each side while parallax is on
std::atomic<int> g_parallax_req{0};
bool  g_px_ready     = false;
Obj   g_px_getter    = nullptr;
int   g_px_left      = -1;
int   g_px_right     = -1;
int   g_px_last      = -1;
float g_px           = 0.0f;
float g_px_target    = 0.0f;
int   g_px_kick_tick = -1000;
int   g_px_on        = -1; // what the view is set up for (-1 unknown)
Obj   g_px_view      = nullptr;

void setup_parallax() {
	g_px_ready  = true;
	Obj pk      = g_plugin != nullptr ? mono_object_get_class(g_plugin) : nullptr;
	Obj prop    = pk != nullptr ? mono_class_get_property_from_name(pk, "TransitionType") : nullptr;
	g_px_getter = prop != nullptr ? mono_property_get_get_method(prop) : nullptr;
	Obj t       = g_px_getter != nullptr && mono_method_signature != nullptr ? mono_signature_get_return_type(mono_method_signature(g_px_getter)) : nullptr;
	Obj ek      = t != nullptr && mono_class_from_mono_type != nullptr ? mono_class_from_mono_type(t) : nullptr;
	Obj vt      = ek != nullptr && mono_class_vtable != nullptr ? mono_class_vtable(g_domain, ek) : nullptr;
	Obj fl      = ek != nullptr ? mono_class_get_field_from_name(ek, "CustomImageSlideInLeft") : nullptr;
	Obj fr      = ek != nullptr ? mono_class_get_field_from_name(ek, "CustomImageSlideInRight") : nullptr;
	if (vt != nullptr && fl != nullptr && fr != nullptr) {
		mono_field_static_get_value(vt, fl, &g_px_left);
		mono_field_static_get_value(vt, fr, &g_px_right);
	}
	wp_log("parallax: TransitionType getter %p, SlideInLeft %d, SlideInRight %d", g_px_getter, g_px_left, g_px_right);
}

void place_view(Obj view, bool parallax, float shift) {
	float x = parallax ? -kOverX + shift : 0.0f, y = parallax ? -kOverY : 0.0f;
	float w = parallax ? 1920.0f + 2 * kOverX : 1920.0f, h = parallax ? 1080.0f + 2 * kOverY : 1080.0f;
	property_set(g_ui3_widget, view, "X", &x);
	property_set(g_ui3_widget, view, "Y", &y);
	property_set(g_ui3_widget, view, "Width", &w);
	property_set(g_ui3_widget, view, "Height", &h);
}

void parallax_tick() {
	Obj       view = g_own_view != nullptr ? g_own_view : g_boot_player;
	const int on   = g_parallax_req.load() == 1 && view != nullptr ? 1 : 0;
	if (view == nullptr) {
		return;
	}
	if (on != g_px_on || view != g_px_view) {
		g_px_on   = on;
		g_px_view = view;
		g_px = g_px_target = 0.0f;
		place_view(view, on == 1, 0.0f);
		wp_log("parallax: %s", on ? "on" : "off");
	}
	if (!on) {
		return;
	}
	if (!g_px_ready) {
		setup_parallax();
	}
	if (g_px_getter == nullptr || g_px_left < 0) {
		return;
	}
	Obj exc = nullptr;
	Obj val = mono_runtime_invoke(g_px_getter, g_plugin, nullptr, &exc);
	const int type = exc == nullptr && val != nullptr ? *static_cast<int*>(mono_object_unbox(val)) : -1;
	if (type != g_px_last) {
		g_px_last = type;
		if (type == g_px_left || type == g_px_right) {
			g_px_target    = type == g_px_left ? 22.0f : -22.0f;
			g_px_kick_tick = g_tick;
		}
	}
	if (g_tick - g_px_kick_tick > 10) {
		g_px_target = 0.0f; // after the nudge, settle back
	}
	const float speed = g_px_target != 0.0f ? 0.18f : 0.07f;
	const float next  = g_px + (g_px_target - g_px) * speed;
	if (next > -0.05f && next < 0.05f && g_px_target == 0.0f) {
		if (g_px != 0.0f) {
			g_px = 0.0f;
			place_view(view, true, 0.0f);
		}
		return;
	}
	g_px = next;
	float x = -kOverX + g_px;
	property_set(g_ui3_widget, view, "X", &x);
}

// ---- crash-loop guard ------------------------------------------------------------------------

bool guard_exists() {
	struct stat st {};
	return stat(kGuardFile, &st) == 0;
}

bool guard_create() {
	mkdir("/system_tmp/liveshell", 0777);
	const int fd = open(kGuardFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		return false;
	}
	close(fd);
	return true;
}

void* guard_thread(void*) {
	sleep(20);
	unlink(kGuardFile);
	wp_log("video: alive after 20 s, guard removed");
	return nullptr;
}

// ---- choose the video clip -------------------------------------------------------------------

bool choose_video() {
	g_video_path[0] = 0;
	FILE* f = fopen(kPathFile, "r");
	if (f != nullptr) {
		char line[512] = {};
		if (fgets(line, sizeof(line), f) != nullptr) {
			line[strcspn(line, "\r\n")] = 0;
			if (line[0] == '/') {
				snprintf(g_video_path, sizeof(g_video_path), "%s", line);
			}
		}
		char mode[64] = {};
		if (fgets(mode, sizeof(mode), f) != nullptr) {
			mode[strcspn(mode, "\r\n")] = 0;
			g_mode_sony = strcmp(mode, "mode=sony") == 0;
		}
		fclose(f);
	}
	if (g_video_path[0] == 0) {
		wp_log("video: no path in %s", kPathFile);
		return false;
	}
	struct stat st {};
	const bool visible = stat(g_video_path, &st) == 0;
	wp_log("video: clip %s (%s), route %s", g_video_path, visible ? "found" : "NOT FOUND",
	       g_mode_sony ? "Sony InitialBootPlayer" : "own player");
	return visible;
}

// ---- PUI.Application.Update detour (our UI-thread tick) --------------------------------------

std::atomic<bool> g_pending{false};
std::atomic<bool> g_video_wanted{false};

// Requests from the window: the watcher thread copies the path file's first line here.
pthread_mutex_t   g_req_lock = PTHREAD_MUTEX_INITIALIZER;
char              g_req_line[512] = {};
std::atomic<bool> g_req_new{false};
bool              g_have_req   = false;
char              g_req_take[512] = {};
bool              g_stopping   = false;
int               g_stop_tick  = 0;
bool              g_welcomed   = false;

bool video_active() {
	return g_own_view != nullptr || g_boot_player != nullptr;
}

// Stop the current clip. Called on the UI thread only. The player itself is not disposed here:
// the view owns it, and a second Dispose on it is not known to be safe.
void stop_video() {
	if (g_own_view != nullptr) {
		Obj view   = g_own_view;
		g_own_view = nullptr; // own_player_report stops touching it from now on
		g_own_player = nullptr;
		Obj stop    = find_method_up(g_videoview_class, "Stop", 0);
		Obj dispose = find_method_up(g_videoview_class, "Dispose", 0);
		wp_log("stop: own view, Stop %p Dispose %p", stop, dispose);
		if (stop != nullptr) {
			invoke(stop, view, nullptr, "VideoView.Stop");
		}
		invoke(dispose, view, nullptr, "VideoView.Dispose");
	}
	if (g_boot_player != nullptr) {
		Obj player    = g_boot_player;
		g_boot_player = nullptr;
		Obj dispose   = find_method_up(g_boot_class, "Dispose", 0);
		wp_log("stop: boot player, Dispose %p", dispose);
		invoke(dispose, player, nullptr, "InitialBootPlayer.Dispose");
	}
	g_own_frames = g_own_logs = g_own_restarts = 0;
	g_own_loop_set = false;
}

int start_video() {
	write_status("starting");
	const int rc = g_mode_sony ? start_video_sony() : start_own_player();
	wp_log("video: start result %d (%s)", rc, g_video_path);
	if (rc == 0) {
		write_status("playing %s", g_video_path);
		raise_dim();
		if (!g_welcomed) {
			g_welcomed = true;
			notify("Welcome to LiveShell Engine 📺");
		}
	} else {
		write_status("failed %d", rc);
		char text[80];
		snprintf(text, sizeof(text), "LiveShell Engine: the video could not start (%d)", rc);
		notify(text);
	}
	return rc;
}

// Switching (UI thread): stop the old clip, give the decoder ~2 s to let go of the file (the daemon
// unmounts its folder after "stopped"), then start the new one if the request is a path.
void handle_requests() {
	if (g_req_new.exchange(false, std::memory_order_acq_rel)) {
		pthread_mutex_lock(&g_req_lock);
		memcpy(g_req_take, g_req_line, sizeof(g_req_take));
		pthread_mutex_unlock(&g_req_lock);
		g_have_req = true;
		wp_log("request: '%s'", g_req_take);
	}
	if (!g_have_req) {
		return;
	}
	if (!g_stopping && video_active()) {
		stop_video();
		g_stopping  = true;
		g_stop_tick = g_tick;
		write_status("stopping");
		return;
	}
	if (g_stopping) {
		if (g_tick - g_stop_tick < 120) {
			return;
		}
		g_stopping = false;
		write_status("stopped");
	}
	g_have_req = false;
	if (g_req_take[0] != '/') {
		write_status("stopped");
		return;
	}
	struct stat st {};
	if (stat(g_req_take, &st) != 0) {
		wp_log("request: %s not visible", g_req_take);
		write_status("failed notfound");
		return;
	}
	snprintf(g_video_path, sizeof(g_video_path), "%s", g_req_take);
	start_video();
}

using UpdateFn = void (*)(Obj self);
UpdateFn g_update_orig = nullptr;

void Update_Hook(Obj self) {
	g_update_orig(self);
	++g_tick;
	video_report();
	own_player_report();
	if (g_installed) {
		handle_requests();
		refresh_dim();
		refresh_blur();
		refresh_looks();
		if (true) { // every frame: the menu fade needs it (just a static field read)
			focus_tick();
			parallax_tick();
		}
	}

	if (!g_pending.exchange(false, std::memory_order_acq_rel)) {
		return;
	}
	if (g_installed) {
		return;
	}
	const int rc = install_bglayer();
	wp_log("setup done (%d)", rc);
	if (rc != 0) {
		write_status("failed setup %d", rc);
		char text[80];
		snprintf(text, sizeof(text), "LiveShell Engine could not start (%d)", rc);
		notify(text);
		return;
	}
	if (!g_video_wanted.load(std::memory_order_acquire)) {
		write_status("stopped");
		return;
	}
	start_video();
	pthread_t gt;
	if (pthread_create(&gt, nullptr, guard_thread, nullptr) == 0) {
		pthread_detach(gt);
	}
}

// ---- background thread: choose clip, then watch the path file for the window's requests ------

void read_request_line(char* out, size_t size) {
	out[0]  = 0;
	FILE* f = fopen(kPathFile, "r");
	if (f == nullptr) {
		return;
	}
	if (fgets(out, static_cast<int>(size), f) != nullptr) {
		out[strcspn(out, "\r\n")] = 0;
	}
	fclose(f);
}

void* wallpaper_thread(void*) {
	sleep(5);
	char seen[512];
	read_request_line(seen, sizeof(seen));
	if (guard_exists()) {
		wp_log("video: last attempt did not survive (%s still there)", kGuardFile);
	} else if (!choose_video()) {
		// strict: the configured video or nothing
	} else if (guard_create()) {
		g_video_wanted.store(true, std::memory_order_release);
	} else {
		wp_log("video: cannot write %s", kGuardFile);
	}
	g_pending.store(true, std::memory_order_release);
	wp_log("queued for the UI thread");

	char now[512];
	for (;;) {
		usleep(300 * 1000);
		if (FILE* f = fopen(kDimFile, "r")) {
			int dim = -1;
			if (fscanf(f, "%d", &dim) == 1 && dim >= 0 && dim <= 90 && dim != g_dim_req.load()) {
				g_dim_req.store(dim);
				wp_log("dim request: %d%%", dim);
			}
			fclose(f);
		}
		if (FILE* f = fopen(kMenusFile, "r")) {
			int menus = 0;
			if (fscanf(f, "%d", &menus) == 1 && (menus == 0 || menus == 1) && menus != g_menus_req.load()) {
				g_menus_req.store(menus);
				wp_log("menus request: %s", menus ? "hide" : "show");
			}
			fclose(f);
		}
		if (FILE* f = fopen(kParallaxFile, "r")) {
			int px = 0;
			if (fscanf(f, "%d", &px) == 1 && (px == 0 || px == 1) && px != g_parallax_req.load()) {
				g_parallax_req.store(px);
				wp_log("parallax request: %d", px);
			}
			fclose(f);
		}
		if (FILE* f = fopen(kLooksFile, "r")) {
			int v[kLooks] = {-1, -1, -1, -1};
			if (fscanf(f, "%d %d %d %d", &v[0], &v[1], &v[2], &v[3]) == 4) {
				for (int l = 0; l < kLooks; ++l) {
					if (v[l] >= 0 && v[l] <= 2 && v[l] != g_look_req[l].load()) {
						g_look_req[l].store(v[l]);
						wp_log("look request: %d -> %d", l, v[l]);
					}
				}
			}
			fclose(f);
		}
		if (FILE* f = fopen(kBlurFile, "r")) {
			int blur = -1;
			if (fscanf(f, "%d", &blur) == 1 && blur >= 0 && blur <= 2 && blur != g_blur_req.load()) {
				g_blur_req.store(blur);
				wp_log("blur request: %d", blur);
			}
			fclose(f);
		}
		read_request_line(now, sizeof(now));
		if (now[0] == 0 || strcmp(now, seen) == 0) {
			continue;
		}
		memcpy(seen, now, sizeof(seen));
		pthread_mutex_lock(&g_req_lock);
		memcpy(g_req_line, now, sizeof(g_req_line));
		pthread_mutex_unlock(&g_req_lock);
		g_req_new.store(true, std::memory_order_release);
	}
	return nullptr;
}

} // namespace

// ---- entry point (called by the daemon's injector) -------------------------------------------

extern "C" int main(int argc, char const* argv[]) {
	(void)argc;
	(void)argv;

	mkdir("/system_tmp/liveshell", 0777);
	g_log   = open(kLogFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	g_t0_ms = now_ms();
	const pid_t pid = getpid();
	wp_log("LiveShell ShellUI module starting (pid %d)", static_cast<int>(pid));

	// The injector is still inside ShellUI for a few ms after starting this thread (breakpoint,
	// register restore, detach). Kernel reads cut by that stop hung the whole process (tests 2, 4, 5),
	// so touch nothing until it is long gone.
	usleep(1500 * 1000);
	wp_log("injector gone, starting");

	pthread_t hb;
	if (pthread_create(&hb, nullptr, heartbeat_thread, nullptr) == 0) {
		pthread_detach(hb);
	}

	// Raised authid for the whole setup, like OnionHEN's toolbox: symbol lookups and the detour's
	// code-page mprotect need it. Dropped once the hook is in.
	g_step.store("set_ucred_to_ptrace");
	const uintptr_t old_authid = set_ucred_to_ptrace();
	wp_log("authid raised (old %#lx)", static_cast<unsigned long>(old_authid));
	auto fail = [&](const char* text, int rc) {
		wp_log("setup failed: %s", text);
		if (old_authid != 0) {
			set_proc_authid(pid, old_authid);
		}
		notify(text);
		return rc;
	};

	if (!resolve_kernel()) {
		return fail("LiveShell Engine could not start (kernel symbols missing)", 1);
	}
	if (!resolve_mono()) {
		return fail("LiveShell Engine could not start (Mono symbols missing)", 1);
	}
	g_step.store("mono_get_root_domain / mono_thread_attach");
	g_domain = mono_get_root_domain();
	mono_thread_attach(g_domain);
	wp_log("Mono domain %p, thread attached", g_domain);

	g_step.store("mprotect probe");
	char probe[100];
	has_hv_bypass = sceKernelMprotect(probe, sizeof(probe), 0x7) == 0;
	wp_log("mprotect probe: has_hv_bypass=%d", has_hv_bypass ? 1 : 0);

	g_step.store("open PUI assembly");
	Obj pui_image = open_image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
	wp_log("PUI image %p", pui_image);
	if (pui_image == nullptr) {
		return fail("LiveShell Engine could not start (PUI not found)", 2);
	}
	g_step.store("compile Application.Update");
	const uint64_t update_addr =
	    get_method_address(pui_image, "Sce.PlayStation.PUI", "Application", "Update", 0);
	wp_log("Application.Update compiled at %#lx", static_cast<unsigned long>(update_addr));
	if (update_addr == 0) {
		return fail("LiveShell Engine could not start (Update not found)", 3);
	}
	g_step.store("InstallDetour(Application.Update)");
	if (!InstallDetour(update_addr, reinterpret_cast<void*>(&Update_Hook),
	                   reinterpret_cast<void**>(&g_update_orig)) ||
	    g_update_orig == nullptr) {
		return fail("LiveShell Engine could not start (hook failed)", 4);
	}
	wp_log("PUI.Application.Update hooked");
	g_step.store("hooked, waiting for UI ticks");

	if (old_authid != 0) {
		set_proc_authid(pid, old_authid);
	}

	pthread_t thread;
	if (pthread_create(&thread, nullptr, wallpaper_thread, nullptr) == 0) {
		pthread_detach(thread);
	} else {
		wp_log("wallpaper_thread start failed");
	}
	wp_log("init done");

	// Never return: the injected ELF (and the detour hook code in it) must stay alive, the same
	// way OnionHEN's toolbox parks its main thread.
	for (;;) {
		sleep(60);
	}
}
