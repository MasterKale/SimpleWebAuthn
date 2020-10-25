//@ts-check

/* eslint-disable @typescript-eslint/no-var-requires */
const { ReflectionKind } = require('typedoc');
const { Converter } = require('typedoc/dist/lib/converter');

/** @param {import("typedoc/dist/lib/utils/plugins").PluginHost} host */
exports.load = function (host) {
  host.application.converter.on(Converter.EVENT_RESOLVE_BEGIN, context => {
    /** @type {import("typedoc").ProjectReflection} */
    const project = context.project;

    for (const mod of project.children.filter(child => child.kind === ReflectionKind.Module)) {
      const tag = mod.comment?.getTag('module');
      if (!tag) continue;
      mod.name = tag.text;
      mod.comment.removeTags('module');
    }
  });
};
