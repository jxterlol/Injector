#include "hooks.hpp"

#include <lapi.h>
#include <lgc.h>
#include <ldebug.h>
#include <Utilitys/Globals.hpp>

#include <RBX/environment/libs/http/http.hpp>
#include <RBX/environment/libs/miscellaneous/miscellaneous.hpp>
#include <RBX/environment/libs/oth/oth.hpp>
#include <RBX/environment/libs/closures/closures.hpp>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_set>

lua_CFunction original_index = nullptr;
lua_CFunction original_namecall = nullptr;

static std::unordered_set<std::string> blocked_funcs = {
    "Load", "OpenScreenshotsFolder", "OpenVideosFolder", "AddCoreScriptLocal",
    "SaveScriptProfilingData", "GetRobuxBalance", "PerformPurchase", "PerformPurchaseV2",
    "PerformBulkPurchase", "PerformSubscriptionPurchase", "PerformSubscriptionPurchaseV2",
    "PerformCancelSubscription", "PromptPurchase", "PromptProductPurchase",
    "PromptGamePassPurchase", "PromptBundlePurchase", "PromptBulkPurchase",
    "PromptRobloxPurchase", "PromptThirdPartyPurchase", "PromptPremiumPurchase",
    "PromptSubscriptionPurchase", "PromptCancelSubscription", "PromptNativePurchase",
    "PromptNativePurchaseWithLocalPlayer", "PromptCollectiblesPurchase",
    "PrepareCollectiblesPurchase", "GetUserSubscriptionPaymentHistoryAsync",
    "GetUserSubscriptionDetailsInternalAsync", "GetUserSubscriptionStatusAsync",
    "ReportAbuse", "ReportAbuseV3", "TakeScreenshot", "ToggleRecording",
    "OpenBrowserWindow", "OpenNativeOverlay", "ExecuteJavaScript", "ReturnToJavaScript",
    "SendCommand", "EmitHybridEvent", "OpenWeChatAuthWindow", "BroadcastNotification",
    "OpenUrl", "DetectUrl", "RegisterLuaUrl", "StartLuaUrlDelivery", "StopLuaUrlDelivery",
    "SwitchToSettingsApp", "SupportsSwitchToSettingsApp", "GetLastLuaUrl",
    "GetAndClearLastPendingUrl", "IsUrlRegistered", "RequestInternal", "requestInternal",
    "RequestAsync", "GetAsync", "PostAsync", "GetAsyncFullUrl", "PostAsyncFullUrl",
    "RequestLimitedAsync", "HttpRequestAsync", "GetApiV1", "InvokeAsync",
    "RegisterOpenCloud", "CaptureScreenshot", "CreatePostAsync", "DeleteCapture",
    "DeleteCapturesAsync", "GetCaptureFilePathAsync", "GetCaptureUploadDataAsync",
    "GetCaptureSizeAsync", "GetCaptureStorageSizeAsync", "RetrieveCaptures",
    "SaveCaptureToExternalStorage", "SaveCapturesToExternalStorageAsync",
    "SaveScreenshotCapture", "PromptSaveCapturesToGallery", "PromptShareCapture",
    "PostToFeedAsync", "Call", "GetLast", "GetMessageId",
    "GetProtocolMethodRequestMessageId", "GetProtocolMethodResponseMessageId",
    "MakeRequest", "Publish", "PublishProtocolMethodRequest",
    "PublishProtocolMethodResponse", "Subscribe", "SubscribeToProtocolMethodRequest",
    "SubscribeToProtocolMethodResponse", "GetCredentialsHeaders", "GetDeviceAccessToken",
    "GetDeviceIntegrityToken", "GetDeviceIntegrityTokenYield", "NoPromptCreateOutfit",
    "NoPromptDeleteOutfit", "NoPromptRenameOutfit", "NoPromptSaveAvatar",
    "NoPromptSaveAvatarThumbnailCustomization", "NoPromptSetFavorite",
    "NoPromptUpdateOutfit", "PerformCreateOutfitWithDescription", "PerformDeleteOutfit",
    "PerformRenameOutfit", "PerformSaveAvatarWithDescription", "PerformSetFavorite",
    "PerformUpdateOutfit", "PromptCreateOutfit", "PromptDeleteOutfit",
    "PromptRenameOutfit", "PromptSaveAvatar", "PromptSetFavorite", "PromptUpdateOutfit",
    "SetAllowInventoryReadAccess", "PromptAllowInventoryReadAccess",
    "SignalCreateOutfitFailed", "SignalCreateOutfitPermissionDenied",
    "SignalDeleteOutfitFailed", "SignalDeleteOutfitPermissionDenied",
    "SignalRenameOutfitFailed", "SignalRenameOutfitPermissionDenied",
    "SignalSaveAvatarPermissionDenied", "SignalSetFavoriteFailed",
    "SignalSetFavoritePermissionDenied", "SignalUpdateOutfitFailed",
    "SignalUpdateOutfitPermissionDenied", "GetLocalFileContents", "SetBaseUrl",
    "FetchAssetWithFormat", "RegisterUGCValidationFunction", "PerformManagedUpdate",
    "SetPurchasePromptIsShown", "DumpToFileAsync", "Run", "OpenInBrowser_DONOTUSE",
    "TryInstallPlugin", "PromptImportFile", "PromptImportFiles", "UninstallPlugin",
};

static std::unordered_set<std::string> blocked_services = {
    "BrowserService", "ScriptContext", "ScriptProfilerService", "MicroProfilerService",
    "TestService", "StudioService", "AccountService", "MessageBusService",
    "OpenCloudService", "HttpRbxApiService", "AvatarEditorService", "CaptureService",
    "LinkingService",
};

static std::string sanitize_key(const char* str, size_t len)
{
    std::string key;
    key.reserve(len);
    for (size_t i = 0; i < len; i++)
    {
        if (str[i] != '\0' && str[i] != '\1')
            key += str[i];
    }
    return key;
}

static bool is_executor_state(lua_State* L)
{
    if (!L)
        return false;

    // threads we created for script execution are executor states by definition
    if (Shared::ExecutorThreads.count(L))
        return true;

    if (!L->userdata)
        return false;

    auto* data = static_cast<RobloxExtraSpace*>(L->userdata);

    if (data->capabilities == Shared::MaxCapabilities)
        return true;

    if (data->script.expired())
        return true;

    return false;
}

#include <RBX/environment/libs/signals/signals.hpp>

static int BindToRenderStep_Wrapper(lua_State* L)
{
    Signals::RecordRenderStepBinding(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
    return lua_gettop(L);
}

static int UnbindFromRenderStep_Wrapper(lua_State* L)
{
    Signals::ForgetRenderStepBindingByArg(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
    return lua_gettop(L);
}

static int signal_connect_wrapper(lua_State* L);

int index_hook(lua_State* L)
{
    if (!is_executor_state(L))
        return original_index(L);

    std::string key;
    if (lua_isstring(L, 2))
    {
        size_t len = 0;
        const char* str = lua_tolstring(L, 2, &len);
        if (str)
            key = sanitize_key(str, len);
    }

    if (key.empty())
        return original_index(L);

    if (blocked_funcs.count(key) > 0)
    {
        luaL_error(L, "attempt to access blocked function '%s'", key.c_str());
        return 0;
    }

    if (is_executor_state(L))
    {
        if (key == "HttpGet" || key == "HttpGetAsync")
        {
            lua_pushcclosure(L, module::core::environment::c_http::http_get, "HttpGet", 0);
            return 1;
        }
        if (key == "HttpPost" || key == "HttpPostAsync")
        {
            lua_pushcclosure(L, module::core::environment::c_http::http_post, "HttpPost", 0);
            return 1;
        }
        else if (key == "GetObjects" || key == "GetObjectsAsync")
        {
            lua_pushcclosure(L, Miscellaneous::GetObjects, "GetObjects", 0);
            return 1;
        }
        else if (key == "BindToRenderStep")
        {
            int res = original_index(L);
            if (res == 1 && lua_isfunction(L, -1))
            {
                lua_pushcclosure(L, BindToRenderStep_Wrapper, "BindToRenderStep", 1);
                return 1;
            }
            return res;
        }
        else if (key == "UnbindFromRenderStep")
        {
            int res = original_index(L);
            if (res == 1 && lua_isfunction(L, -1))
            {
                lua_pushcclosure(L, UnbindFromRenderStep_Wrapper, "UnbindFromRenderStep", 1);
                return 1;
            }
            return res;
        }
        else if (key == "Connect" || key == "Once" || key == "ConnectParallel")
        {
            // signal methods resolved through __index (signal metatable shares
            // the instance __index closure) still need the tracking wrapper so
            // getconnections can answer Function/Thread from our records
            int res = original_index(L);
            if (res == 1 && lua_isfunction(L, -1))
            {
                lua_pushcclosure(L, signal_connect_wrapper, ("Connection.Connect"), 1);
                return 1;
            }
            return res;
        }
    }

    return original_index(L);
}

static lua_CFunction original_signal_index = nullptr;
static lua_CFunction original_signal_namecall = nullptr;

static int signal_connect_wrapper(lua_State* L)
{
    const int nargs = lua_gettop(L);

    // re-issue the original call with the arguments duplicated so the real
    // self/function survive on the stack for connection tracking
    for (int i = 1; i <= nargs; ++i)
        lua_pushvalue(L, i);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, nargs + 1);
    lua_call(L, nargs, LUA_MULTRET);

    const int nres = lua_gettop(L) - nargs;

    if (nres >= 1 && nargs >= 2 && is_executor_state(L) &&
        lua_isfunction(L, 2) && lua_isuserdata(L, nargs + 1))
    {
        lua_pushvalue(L, 2);
        const int funcRef = lua_ref(L, -1);
        lua_pop(L, 1);
        if (funcRef > 0 && Signals::GetSignalIdentity(L, 1) != 0)
        {
            Signals::TrackConnection(
                L, 1,
                reinterpret_cast<std::uintptr_t>(lua_touserdata(L, nargs + 1)),
                funcRef);
        }
    }

    return nres;
}

static int signal_index_hook(lua_State* L)
{
    const int n = original_signal_index(L);
    if (n == 1 && lua_isfunction(L, -1) && is_executor_state(L))
    {
        const char* key = lua_isstring(L, 2) ? lua_tostring(L, 2) : nullptr;
        if (key && (std::string(key) == ("Connect") ||
            std::string(key) == ("Once") ||
            std::string(key) == ("ConnectParallel")))
        {
            // the original method becomes the wrapper's upvalue
            lua_pushcclosure(L, signal_connect_wrapper, ("Connection.Connect"), 1);
            return 1;
        }
    }
    return n;
}

static int signal_namecall_hook(lua_State* L)
{
    if (is_executor_state(L) && L->namecall)
    {
        const char* str = L->namecall->data;
        const size_t len = L->namecall->len;
        const std::string key = str ? std::string(str, len) : std::string();
        if (key == ("Connect") || key == ("Once") || key == ("ConnectParallel"))
        {
            const int results = original_signal_namecall(L);
            if (results >= 1 && lua_isfunction(L, 2))
            {
                lua_pushvalue(L, 2);
                const int funcRef = lua_ref(L, -1);
                lua_pop(L, 1);
                const int connIdx = lua_gettop(L) - results + 1;
                if (funcRef > 0 && Signals::GetSignalIdentity(L, 1) != 0)
                {
                    Signals::TrackConnection(
                        L, 1,
                        reinterpret_cast<std::uintptr_t>(lua_touserdata(L, connIdx)),
                        funcRef);
                }
            }
            return results;
        }
    }
    return original_signal_namecall(L);
}

int namecall_hook(lua_State* L)
{
    if (!is_executor_state(L))
        return original_namecall(L);

    std::string key;
    if (L->namecall)
    {
        const char* str = L->namecall->data;
        size_t len = L->namecall->len;
        if (str)
            key = sanitize_key(str, len);
    }

    if (key.empty())
        return original_namecall(L);

    if (blocked_services.count(key) > 0)
    {
        luaL_error(L, "attempt to access blocked service '%s'", key.c_str());
        return 0;
    }

    if (blocked_funcs.count(key) > 0)
    {
        luaL_error(L, "attempt to access blocked function '%s'", key.c_str());
        return 0;
    }

    if (is_executor_state(L))
    {
        if (key == "HttpGet" || key == "HttpGetAsync")
            return module::core::environment::c_http::http_get(L);
        else if (key == "GetObjects" || key == "GetObjectsAsync")
            return Miscellaneous::GetObjects(L);
        else if (key == "BindToRenderStep")
        {
            Signals::RecordRenderStepBinding(L);
            return original_namecall(L);
        }
        else if (key == "UnbindFromRenderStep")
        {
            Signals::ForgetRenderStepBindingByArg(L);
            return original_namecall(L);
        }
        else if (key == "Connect" || key == "Once" || key == "ConnectParallel")
        {
            // record executor-side connections so getconnections can expose
            // Function/Thread when the native slot read is not available
            const int results = original_namecall(L);
            if (results >= 1 && lua_isfunction(L, 2))
            {
                lua_pushvalue(L, 2);
                const int funcRef = lua_ref(L, -1);
                lua_pop(L, 1);
                const int connIdx = lua_gettop(L) - results + 1;
                if (funcRef > 0 && Signals::GetSignalIdentity(L, 1) != 0)
                {
                    Signals::TrackConnection(
                        L, 1,
                        reinterpret_cast<std::uintptr_t>(lua_touserdata(L, connIdx)),
                        funcRef);
                }
            }
            return results;
        }
    }

    return original_namecall(L);
}

void initialize_hooks(lua_State* L)
{
    int original_top = lua_gettop(L);

    lua_getglobal(L, "game");

    luaL_getmetafield(L, -1, "__index");
    if (lua_type(L, -1) == LUA_TFUNCTION)
    {
        Closure* index_closure = clvalue(luaA_toobject(L, -1));
        if (original_index == nullptr)
            original_index = index_closure->c.f;
        index_closure->c.f = index_hook;
    }
    lua_pop(L, 1);

    luaL_getmetafield(L, -1, "__namecall");
    if (lua_type(L, -1) == LUA_TFUNCTION)
    {
        Closure* namecall_closure = clvalue(luaA_toobject(L, -1));
        if (original_namecall == nullptr)
            original_namecall = namecall_closure->c.f;
        namecall_closure->c.f = namecall_hook;
    }
    lua_pop(L, 1);

    // RBXScriptSignal keeps its own metatable (unless Roblox shares the
    // closures above); patch it too so executor-side :Connect() calls are
    // tracked and getconnections can answer Function/Thread
    lua_getglobal(L, "Instance");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, ("new"));
        if (lua_isfunction(L, -1))
        {
            lua_pushstring(L, "BindableEvent");
            if (lua_pcall(L, 1, 1, 0) == 0)
            {
                if (lua_isuserdata(L, -1))
                {
                    lua_getfield(L, -1, ("Event"));
                    if (lua_isuserdata(L, -1))
                    {
                        luaL_getmetafield(L, -1, "__index");
                        if (lua_type(L, -1) == LUA_TFUNCTION)
                        {
                            Closure* c = clvalue(luaA_toobject(L, -1));
                            if (c->c.f != index_hook && c->c.f != signal_index_hook)
                            {
                                if (original_signal_index == nullptr)
                                    original_signal_index = c->c.f;
                                c->c.f = signal_index_hook;
                            }
                        }
                        lua_pop(L, 1);

                        luaL_getmetafield(L, -1, "__namecall");
                        if (lua_type(L, -1) == LUA_TFUNCTION)
                        {
                            Closure* c = clvalue(luaA_toobject(L, -1));
                            if (c->c.f != namecall_hook && c->c.f != signal_namecall_hook)
                            {
                                if (original_signal_namecall == nullptr)
                                    original_signal_namecall = c->c.f;
                                c->c.f = signal_namecall_hook;
                            }
                        }
                        lua_pop(L, 1);
                    }
                    lua_pop(L, 1); // Event value
                    lua_pop(L, 1); // instance
                }
                else
                {
                    lua_pop(L, 1); // unexpected pcall result
                }
            }
            else
            {
                lua_pop(L, 1); // pcall error
            }
        }
        else
        {
            lua_pop(L, 1); // Instance.new missing
        }
    }
    lua_pop(L, 1); // Instance

    lua_settop(L, original_top);
}
