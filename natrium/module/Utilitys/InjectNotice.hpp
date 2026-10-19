#pragma once

// Built-in "injected successfully" toast.
//
// The notification Lua lives HERE, inside the module, and is queued
// internally on every successful init - it is never sent over the wire,
// never read from disk, and never exists as plaintext in the binary:
// the source below is XOR-scrambled at COMPILE time (constexpr) so a
// strings-dump of natrium.dll only shows ciphertext, and it is decoded
// at runtime just before execution. {{CLIENT_VERSION}} is stamped with
// the real client version from FFlagOffsets at that moment.

#include <RBX/fflags.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace InjectNotice
{
    inline constexpr const char kVersionTag[] = "{{CLIENT_VERSION}}";
    inline constexpr uint8_t kKey = 0x9E;

    inline constexpr const char kRaw[] = R"NOTICE(
local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")

local player = Players.LocalPlayer
local gui = Instance.new("ScreenGui")
gui.Name = "SodiumNotification"
gui.ResetOnSpawn = false
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Name = "Notification"
frame.Size = UDim2.fromOffset(340, 86)
frame.Position = UDim2.new(1, -20, 1, -24)
frame.AnchorPoint = Vector2.new(1, 1)
frame.BackgroundColor3 = Color3.fromRGB(25, 25, 25)
frame.BackgroundTransparency = 1
frame.BorderSizePixel = 0
frame.Parent = gui

local corner = Instance.new("UICorner")
corner.CornerRadius = UDim.new(0, 9)
corner.Parent = frame

local stroke = Instance.new("UIStroke")
stroke.Color = Color3.fromRGB(69, 69, 69)
stroke.Thickness = 1
stroke.Transparency = 1
stroke.Parent = frame

local accent = Instance.new("Frame")
accent.Size = UDim2.new(0, 3, 1, -20)
accent.Position = UDim2.fromOffset(0, 10)
accent.BackgroundColor3 = Color3.fromRGB(95, 198, 106)
accent.BackgroundTransparency = 1
accent.BorderSizePixel = 0
accent.Parent = frame

local accentCorner = Instance.new("UICorner")
accentCorner.CornerRadius = UDim.new(1, 0)
accentCorner.Parent = accent

local title = Instance.new("TextLabel")
title.BackgroundTransparency = 1
title.Position = UDim2.fromOffset(17, 12)
title.Size = UDim2.new(1, -35, 0, 20)
title.Font = Enum.Font.GothamMedium
title.Text = "Sodium v1.6"
title.TextSize = 14
title.TextColor3 = Color3.fromRGB(225, 225, 225)
title.TextTransparency = 1
title.TextXAlignment = Enum.TextXAlignment.Left
title.Parent = frame

local status = Instance.new("TextLabel")
status.BackgroundTransparency = 1
status.Position = UDim2.new(1, -86, 0, 13)
status.Size = UDim2.fromOffset(72, 18)
status.Font = Enum.Font.GothamMedium
status.Text = "CONNECTED"
status.TextSize = 10
status.TextColor3 = Color3.fromRGB(117, 201, 130)
status.TextTransparency = 1
status.TextXAlignment = Enum.TextXAlignment.Right
status.Parent = frame

local message = Instance.new("TextLabel")
message.BackgroundTransparency = 1
message.Position = UDim2.fromOffset(17, 36)
message.Size = UDim2.new(1, -30, 0, 18)
message.Font = Enum.Font.Gotham
message.Text = "Successfully established connection"
message.TextSize = 11
message.TextColor3 = Color3.fromRGB(200, 200, 200)
message.TextTransparency = 1
message.TextXAlignment = Enum.TextXAlignment.Left
message.Parent = frame

local subtext = Instance.new("TextLabel")
subtext.BackgroundTransparency = 1
subtext.Position = UDim2.fromOffset(17, 57)
subtext.Size = UDim2.new(1, -30, 0, 16)
subtext.Font = Enum.Font.Gotham
subtext.Text = "{{CLIENT_VERSION}}"
subtext.TextSize = 10
subtext.TextColor3 = Color3.fromRGB(135, 135, 135)
subtext.TextTransparency = 1
subtext.TextXAlignment = Enum.TextXAlignment.Left
subtext.Parent = frame

-- Fade in
local fadeInInfo = TweenInfo.new(
    0.5,
    Enum.EasingStyle.Quad,
    Enum.EasingDirection.Out
)

local fadeInTweens = {
    TweenService:Create(frame, fadeInInfo, {
        BackgroundTransparency = 0
    }),
    TweenService:Create(stroke, fadeInInfo, {
        Transparency = 0
    }),
    TweenService:Create(accent, fadeInInfo, {
        BackgroundTransparency = 0
    }),
    TweenService:Create(title, fadeInInfo, {
        TextTransparency = 0
    }),
    TweenService:Create(status, fadeInInfo, {
        TextTransparency = 0
    }),
    TweenService:Create(message, fadeInInfo, {
        TextTransparency = 0
    }),
    TweenService:Create(subtext, fadeInInfo, {
        TextTransparency = 0
    })
}

for _, tween in ipairs(fadeInTweens) do
    tween:Play()
end

-- Stay visible for twice as long
task.wait(8)

-- Fade out
local fadeOutInfo = TweenInfo.new(
    0.5,
    Enum.EasingStyle.Quad,
    Enum.EasingDirection.In
)

local fadeOutTweens = {
    TweenService:Create(frame, fadeOutInfo, {
        BackgroundTransparency = 1
    }),
    TweenService:Create(stroke, fadeOutInfo, {
        Transparency = 1
    }),
    TweenService:Create(accent, fadeOutInfo, {
        BackgroundTransparency = 1
    }),
    TweenService:Create(title, fadeOutInfo, {
        TextTransparency = 1
    }),
    TweenService:Create(status, fadeOutInfo, {
        TextTransparency = 1
    }),
    TweenService:Create(message, fadeOutInfo, {
        TextTransparency = 1
    }),
    TweenService:Create(subtext, fadeOutInfo, {
        TextTransparency = 1
    })
}

for _, tween in ipairs(fadeOutTweens) do
    tween:Play()
end

task.wait(0.55)
gui:Destroy()
)NOTICE";

    template <size_t N>
    struct Blob
    {
        uint8_t b[N];
    };

    template <size_t N>
    constexpr Blob<N> EncodeBlob(const char (&s)[N])
    {
        Blob<N> o{};
        for (size_t i = 0; i < N; ++i)
        {
            o.b[i] = static_cast<uint8_t>(
                static_cast<uint8_t>(s[i]) ^
                static_cast<uint8_t>(kKey + ((i * 0x47) & 0xFF)) ^
                static_cast<uint8_t>(i & 0xFF));
        }
        return o;
    }

    inline constexpr auto kEncoded = EncodeBlob(kRaw);

    inline std::string BuildScript()
    {
        std::string s;
        s.resize(sizeof(kEncoded.b) - 1); // drop trailing NUL
        for (size_t i = 0; i < s.size(); ++i)
        {
            s[i] = static_cast<char>(static_cast<uint8_t>(
                kEncoded.b[i] ^
                static_cast<uint8_t>(i & 0xFF) ^
                static_cast<uint8_t>(kKey + ((i * 0x47) & 0xFF))));
        }
        const std::string tag(kVersionTag);
        size_t pos = 0;
        while ((pos = s.find(tag, pos)) != std::string::npos)
        {
            s.replace(pos, tag.size(), FFlagOffsets::ClientVersion);
            pos += FFlagOffsets::ClientVersion.size();
        }
        return s;
    }
} // namespace InjectNotice
