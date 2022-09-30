# Copyright DST Group. Licensed under the MIT license.

import pkgutil
import sys
import inspect


class Plugins:

    def __init__(self, plugin_dir):

        self.loadMenuItemsFromPlugins(self, plugin_dir)

    actions_dict = {"Blue": [], "Red": []}

    @staticmethod
    def getActionNames(self, action_type: str):
        """
        Return a list of all of the actions available for a particular type.
        """
        return [o.name for o in self.actions_dict[action_type]]

    @staticmethod
    def getActionByName(self,  action_type: str, name: str):

        """
        Return an action for a given name for a particular type.
        """
        return self.actions_dict(action_type)[name]


    @staticmethod
    def loadMenuItemsFromPlugins(self, plugin_dir):
        default_plugin_dir = "Shared\Plugins"

        if plugin_dir is None:
            plugin_dir = default_plugin_dir

        # This is from https://stackoverflow.com/questions/1057431/how-to-load-all-modules-in-a-folder

        for importer, package_name, _ in pkgutil.iter_modules([plugin_dir]):
            full_package_name = '%s.%s' % (plugin_dir, package_name)

            if full_package_name not in sys.modules:
                # print("full_package_name=%s\n" % full_package_name)
                # print("package_name=%s\n" % package_name)

                module = importer.find_module(package_name).load_module(full_package_name)

                print("module=%s\n" % str(module))

                members = inspect.getmembers(module)

                for member in members:  # Only add tuple with "CybORGPlugin", but excluding the base class

                    if member[0].find(str("CybORGPlugin")) > -1 and len(member[0]) > len("CybORGPlugin"):
                        plugin_object = member[1]()
                        self.actions_dict[plugin_object.PluginType].append(plugin_object)
