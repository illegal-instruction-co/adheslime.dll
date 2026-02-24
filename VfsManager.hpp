#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace adheslime::vfs {

class Device {
public:
    virtual ~Device() = default;
    virtual bool Read(const std::string& path, std::vector<char>& outData) = 0;
};

class PackfileDevice final : public Device {
private:
    std::map<std::string, std::string> _files;

public:
    void AddFile(const std::string& path, const std::string& content) {
        _files[path] = content;
    }

    bool Read(const std::string& path, std::vector<char>& outData) override {
        if (auto it = _files.find(path); it != _files.end()) {
            const std::string& content = it->second;
            outData.assign(content.begin(), content.end());
            return true;
        }
        return false;
    }
};

class Manager final {
private:
    std::map<std::string, std::unique_ptr<Device>> _mounts;

    Manager() = default;

public:
    static Manager& Get() {
        static Manager instance;
        return instance;
    }

    void Mount(const std::string& mountPoint, std::unique_ptr<Device> device) {
        _mounts[mountPoint] = std::move(device);
    }

    bool ReadFile(const std::string& virtualPath, std::vector<char>& outData) {
        for (const auto& [mountPoint, device] : _mounts) {
            if (virtualPath.starts_with(mountPoint)) {
                std::string relativePath = virtualPath.substr(mountPoint.length());
                return device->Read(relativePath, outData);
            }
        }
        return false;
    }
};

} // namespace adheslime::vfs
