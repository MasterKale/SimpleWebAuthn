const sourcePath = './src';
const outputPaths = [
  '../browser/src/types/',
  '../server/src/types/',
];
const sourceFiles = Deno.readDirSync(sourcePath);

const codegenNotice = `
// deno-fmt-ignore-file
/**
 * DO NOT MODIFY THESE FILES!
 *
 * These files were copied from the **types** package. To update this file, make changes to those
 * files instead and then run the following command from the monorepo root folder:
 *
 * deno task codegen:types
 */
// BEGIN CODEGEN
`;

/**
 * Copy files to each output target
 */
for (const outputPath of outputPaths) {
  console.log(`DESTINATION: ${outputPath}`);

  try {
    // Make sure the folder exists in the target package
    console.log(`Making sure output folder exists...`);
    await Deno.mkdir(outputPath);
  } catch (_err) {
    // The folder already exists, keep going
  }

  for (const file of sourceFiles) {
    if (file.isFile) {
      const fileInputPath = `${sourcePath}/${file.name}`;
      const fileOutputPath = `${outputPath}/${file.name}`;

      // Read in original file
      let fileContents = await Deno.readTextFile(fileInputPath);

      // Make sure the output file exists
      await Deno.create(fileOutputPath);

      // Trim some content from the files being copied over
      fileContents = fileContents.replace('// deno-fmt-ignore-file\n', '');
      fileContents = fileContents.replace('// BEGIN CODEGEN\n', '');

      // Prepend the codegen notice to the file contents
      const fileContentsWithNotice = `${codegenNotice}${fileContents}`;

      // Write the file
      console.log(`Writing ${fileOutputPath}...`);
      await Deno.writeTextFile(fileOutputPath, fileContentsWithNotice);
    }
  }
}
