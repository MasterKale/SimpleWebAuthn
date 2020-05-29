(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "typedoc/dist/lib/converter/plugins", "lodash", "semver", "typedoc/dist/lib/models/reflections/abstract", "typedoc/dist/lib/models/reflections/declaration"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    const plugins_1 = require("typedoc/dist/lib/converter/plugins");
    const lodash_1 = require("lodash");
    const semver_1 = require("semver");
    const abstract_1 = require("typedoc/dist/lib/models/reflections/abstract");
    const declaration_1 = require("typedoc/dist/lib/models/reflections/declaration");
    const typedocVersion = require('typedoc/package.json').version;
    function checkTypedocVersion(semverString) {
        return semver_1.satisfies(typedocVersion, semverString);
    }
    exports.isTypedocVersion = lodash_1.memoize(checkTypedocVersion);
    function removeTags(comment, tag) {
        return plugins_1.CommentPlugin.removeTags(comment, tag);
        // if (exports.isTypedocVersion('< 0.17.0')) {
        //     return plugins_1.CommentPlugin.removeTags(comment, tag);
        // }
        // else {
        //     comment.removeTags(tag);
        // }
    }
    exports.removeTags = removeTags;
    function removeReflection(project, reflection) {
        if (exports.isTypedocVersion('< 0.17.0')) {
            plugins_1.CommentPlugin.removeReflection(project, reflection);
        }
        else {
            project.removeReflection(reflection, true);
        }
        if (exports.isTypedocVersion('>=0.16.0')) {
            delete project.reflections[reflection.id];
        }
    }
    exports.removeReflection = removeReflection;
    function createChildReflection(parent, name) {
        if (exports.isTypedocVersion('< 0.14.0')) {
            return new declaration_1.DeclarationReflection(parent, name, abstract_1.ReflectionKind.Module);
        }
        else {
            return new declaration_1.DeclarationReflection(name, abstract_1.ReflectionKind.Module, parent);
        }
    }
    exports.createChildReflection = createChildReflection;
    /**
     * When we delete reflections, update the symbol mapping in order to fix:
     * https://github.com/christopherthielen/typedoc-plugin-external-module-name/issues/313
     * https://github.com/christopherthielen/typedoc-plugin-external-module-name/issues/193
     */
    function updateSymbolMapping(context, symbol, reflection) {
        if (!symbol) {
            return;
        }
        if (exports.isTypedocVersion('< 0.16.0')) {
            // (context as any).registerReflection(reflection, null, symbol);
            context.project.symbolMapping[symbol.id] = reflection.id;
        }
        else {
            // context.registerReflection(reflection, symbol);
            const fqn = context.checker.getFullyQualifiedName(symbol);
            context.project.fqnToReflectionIdMap.set(fqn, reflection.id);
        }
    }
    exports.updateSymbolMapping = updateSymbolMapping;
    function isModuleOrNamespace(reflection) {
        if (exports.isTypedocVersion('< 0.17.0')) {
            return reflection.kindOf(abstract_1.ReflectionKind.ExternalModule) || reflection.kindOf(abstract_1.ReflectionKind.Module);
        }
        else {
            return reflection.kindOf(abstract_1.ReflectionKind.Module) || reflection.kindOf(abstract_1.ReflectionKind.Namespace);
        }
    }
    exports.isModuleOrNamespace = isModuleOrNamespace;
});
