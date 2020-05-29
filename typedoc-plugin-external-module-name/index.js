/* eslint-disable @typescript-eslint/no-var-requires */
var plugin = require('./typedoc-plugin-external-module-name');
module.exports = function(PluginHost) {
  var app = PluginHost.owner;
  app.converter.addComponent('external-module-name', plugin.ExternalModuleNamePlugin);
};
