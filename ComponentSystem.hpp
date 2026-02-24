#pragma once
#include <map>
#include <string>
#include <memory>
#include <vector>

/**
 * Component registry pattern
 */

namespace ac {
    class Component {
    public:
        virtual ~Component() = default;
        virtual const char* GetName() const = 0;
    };

    class ComponentRegistry final {
    private:
        std::map<std::string, std::shared_ptr<Component>> _components;
        ComponentRegistry() = default;

    public:
        static ComponentRegistry& GetInstance() {
            static ComponentRegistry instance;
            return instance;
        }

        template<typename T>
        void Register(std::shared_ptr<T> component) {
            _components[component->GetName()] = component;
        }

        Component* GetComponent(const std::string& name) {
            if (auto it = _components.find(name); it != _components.end()) return it->second.get();
            return nullptr;
        }

        std::vector<std::string> ListComponents() {
            std::vector<std::string> names;
            for (const auto& [name, _] : _components) names.push_back(name);
            return names;
        }
    };
}
