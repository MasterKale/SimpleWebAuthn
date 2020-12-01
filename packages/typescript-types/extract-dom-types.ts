// n.b. ts-morph is a sibling devDependency of typescript, so that the module
// loader will resolve our project's typescript package, not the transient
// dependency of ts-morph. We only want to reference our typescript dependency
// for its version and its lib.dom.d.ts file. If any typescript functionality
// is needed, use import { ts } from "ts-morph";
import {
  InterfaceDeclaration,
  Node,
  Project,
  Structure,
  SyntaxKind,
  TypeAliasDeclaration,
} from 'ts-morph';
import { version } from 'typescript';

// List of types we directly reference from the dom lib. Only interface and type
// alias identifiers are valid, since other syntax types (class, function, var)
// are implementations, which will not be available outside of the browser.
const types = [
  'AuthenticatorAssertionResponse',
  'AttestationConveyancePreference',
  'AuthenticatorAttestationResponse',
  'AuthenticatorTransport',
  'AuthenticationExtensionsClientInputs',
  'AuthenticatorSelectionCriteria',
  'COSEAlgorithmIdentifier',
  'PublicKeyCredential',
  'PublicKeyCredentialCreationOptions',
  'PublicKeyCredentialDescriptor',
  'PublicKeyCredentialParameters',
  'PublicKeyCredentialRequestOptions',
  'PublicKeyCredentialUserEntity',
  'UserVerificationRequirement',
];

const project = new Project({ skipAddingFilesFromTsConfig: true });
const domSourcePath = 'typescript/lib/lib.dom.d.ts';
const domSourceFile = project.addSourceFileAtPath(require.resolve(domSourcePath));
const resolvedNodes = new Set<InterfaceDeclaration | TypeAliasDeclaration>();
const unresolvedNodes = new Set<InterfaceDeclaration | TypeAliasDeclaration>(
  types.map(type => {
    const node = domSourceFile.getInterface(type) ?? domSourceFile.getTypeAlias(type);
    if (!node) {
      throw new Error(`${type} does not refer to an interface or type alias`);
    }
    return node;
  }),
);

while (unresolvedNodes.size > 0) {
  for (const node of unresolvedNodes.values()) {
    unresolvedNodes.delete(node);
    resolvedNodes.add(node);

    // Declarations in lib files are never exported because they are globally
    // available. Since we are extracting the types to a module, we export them.
    node.setIsExported(true);

    // Find all descendant identifiers which reference an interface or type
    // alias, and add them to the unresolved list.
    for (const id of node.getDescendantsOfKind(SyntaxKind.Identifier)) {
      for (const dn of id.getDefinitionNodes()) {
        if (Node.isInterfaceDeclaration(dn) || Node.isTypeAliasDeclaration(dn)) {
          if (!resolvedNodes.has(dn)) {
            unresolvedNodes.add(dn);
          }
        }
      }
    }
  }
}

const outputSourceFile = project.createSourceFile(`src/dom.ts`, undefined, { overwrite: true });
outputSourceFile.addStatements([
  `// Generated from typescript@${version} ${domSourcePath}`,
  `// To regenerate, run the following command from the project root:`,
  `// npx lerna --scope=@simplewebauthn/typescript-types exec -- npm run extract-dom-types`,
]);
const resolvedStructures = Array.from(resolvedNodes).map(node => node.getStructure());
outputSourceFile.addInterfaces(resolvedStructures.filter(Structure.isInterface));
outputSourceFile.addTypeAliases(resolvedStructures.filter(Structure.isTypeAlias));
outputSourceFile.saveSync();
