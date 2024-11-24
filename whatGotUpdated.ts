/**
 * A script to determine which workspace packages contain code that's been updated since the last
 * git tag version. These packages will become candidates for version bumps.
 */

// Grab workspace folders from root deno.json
import rootDenoJSON from './deno.json' with { type: 'json' };

// Trim relative path specifier so we end up with ["packages/browser", ...]
const workspaceDirs = rootDenoJSON.workspace.map((path) => path.substring(2));

// Check which files have been updated since the last git tag
console.log('Getting latest version tag...');
const latestTag = await getLatestVersionTag();

console.log(`Getting files changed since tag ${latestTag}...`);
const changedFiles = await getChangedFilesSinceTag(latestTag);

// Determine which of the three packages have been changed
console.log('Checking which workspace packages have changed...');
const changedPackages = getChangedWorkspacePackages(changedFiles, workspaceDirs);

/**
 * Determine final output
 */
if (changedPackages.length < 1) {
  console.log('✅ No workspace packages have been updated since the last version tag');
} else {
  console.log('The following workspace packages need new versions published:');

  for (const matched of changedPackages) {
    // Read current versions from corresponding deno.json files
    const packageDenoJSONPath = `./${matched}/deno.json`;
    const { default: packageDenoJSON } = await import(packageDenoJSONPath, {
      with: { type: 'json' },
    });

    // Output package names and their current versions to consider incrementing
    const formattedMatched = `@simplewebauthn/${matched.split('/')[1]}`;
    console.log(
      `📦 ${formattedMatched} (current version: ${packageDenoJSON.version} @ ${packageDenoJSONPath})`,
    );
  }
}

/**
 * Grab the latest version tag from Git
 */
async function getLatestVersionTag(): Promise<string> {
  const command = new Deno.Command('git', {
    args: [
      'describe',
      '--tags',
      '--abbrev=0',
    ],
  });

  const { code, stdout, stderr } = await command.output();

  if (code !== 0) {
    throw new Error(new TextDecoder().decode(stderr));
  }

  const output = new TextDecoder().decode(stdout);
  const toReturn = output.trim();

  // Verify we got something back that looks like a typical version tag
  if (!toReturn.match(/v\d+.\d+.\d+/i)) {
    throw new Error(`Tag "${toReturn}" was not the expected version tag format of vXX.XX.XX`);
  }

  return toReturn;
}

/**
 * Get the list of files changed since the provided version tag
 */
async function getChangedFilesSinceTag(tagName: string): Promise<string[]> {
  const command = new Deno.Command('git', {
    args: [
      'diff',
      '--name-only',
      `${tagName}..HEAD`,
    ],
  });

  const { code, stdout, stderr } = await command.output();

  if (code !== 0) {
    throw new Error(new TextDecoder().decode(stderr));
  }

  const output = new TextDecoder().decode(stdout);

  const toReturn = output.split('\n');

  return toReturn;
}

/**
 * Look through the list of files to figure out which workspace packages have changed
 */
function getChangedWorkspacePackages(changedFiles: string[], workspaceDirs: string[]): string[] {
  const matchedPackages = new Set<string>();

  for (const file of changedFiles) {
    for (const workspace of workspaceDirs) {
      // Check if a package's source code has been modified
      if (file.startsWith(`${workspace}/src`)) {
        matchedPackages.add(workspace);
      }
    }
  }

  return matchedPackages.values().toArray();
}
