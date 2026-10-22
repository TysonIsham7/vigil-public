import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const safariRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Each target keeps a unique wrapper name. Layout paths such as
 * CONTENTS_FOLDER_PATH and INFOPLIST_PATH stay unset so Xcode puts them inside
 * that wrapper. Setting them by hand writes Info.plist and Contents into the
 * products directory, and the .app/.appex is never produced.
 */
const PRODUCTS = {
  "Vigil macOS": {
    productType: "com.apple.product-type.application",
    fileType: "wrapper.application",
    path: "VigilMac.app",
    sdk: "macosx",
    infoPlist: "macOS (App)/Info.plist",
    bundleId: "com.example.vigil.macos",
  },
  "Vigil iOS": {
    productType: "com.apple.product-type.application",
    fileType: "wrapper.application",
    path: "VigilIOS.app",
    sdk: "iphoneos",
    infoPlist: "iOS (App)/Info.plist",
    bundleId: "com.example.vigil.ios",
    platforms: ["iphoneos", "iphonesimulator"],
  },
  "Vigil macOS Extension": {
    productType: "com.apple.product-type.app-extension",
    fileType: "wrapper.app-extension",
    path: "VigilMacExtension.appex",
    sdk: "macosx",
    infoPlist: "macOS (Extension)/Info.plist",
    bundleId: "com.example.vigil.macos.extension",
  },
  "Vigil iOS Extension": {
    productType: "com.apple.product-type.app-extension",
    fileType: "wrapper.app-extension",
    path: "VigilIOSExtension.appex",
    sdk: "iphoneos",
    infoPlist: "iOS (Extension)/Info.plist",
    bundleId: "com.example.vigil.ios.extension",
    platforms: ["iphoneos", "iphonesimulator"],
  },
  "Vigil macOS Tests": {
    productType: "com.apple.product-type.bundle.unit-test",
    fileType: "wrapper.cfbundle",
    path: "VigilTests.xctest",
    sdk: "macosx",
    infoPlist: "Vigil macOS Tests/Info.plist",
    bundleId: "com.example.vigil.macos.tests",
  },
};

const WRAPPER_OVERRIDES = [
  "CONTENTS_FOLDER_PATH",
  "EXECUTABLE_FOLDER_PATH",
  "EXECUTABLE_PATH",
  "INFOPLIST_PATH",
  "UNLOCALIZED_RESOURCES_FOLDER_PATH",
  "WRAPPER_EXTENSION",
  "WRAPPER_NAME",
  "PRODUCT_BUNDLE_PACKAGE_TYPE",
];

export function checkIosExtension(root = safariRoot) {
  const errors = [];
  const project = readFileSync(join(root, "Vigil.xcodeproj/project.pbxproj"), "utf8");
  const plist = readFileSync(join(root, "iOS (Extension)/Info.plist"), "utf8");
  const objects = parseObjects(project);
  const targets = [...objects.values()].filter((item) => item.isa === "PBXNativeTarget");
  if (targets.length < 5) errors.push(`expected 5 native targets, found ${targets.length}`);

  const productNames = new Map();
  const productPaths = new Map();
  for (const target of targets) {
    const configs = configurations(objects, target);
    if (configs.length < 2) errors.push(`${target.name} is missing Debug and Release settings`);
    const names = configs.map((config) => setting(config.body, "PRODUCT_NAME"));
    if (new Set(names).size !== 1 || !names[0]) errors.push(`${target.name} PRODUCT_NAME differs across configurations`);
    const productName = names[0];
    if (productName && /\s/.test(productName)) errors.push(`${target.name} PRODUCT_NAME contains whitespace: ${productName}`);
    if (productName && productNames.has(productName)) {
      errors.push(`PRODUCT_NAME ${productName} is used by ${productNames.get(productName)} and ${target.name}`);
    } else if (productName) productNames.set(productName, target.name);

    const product = objects.get(target.productReference);
    const productPath = product ? setting(product.body, "path") : null;
    if (!productPath) errors.push(`${target.name} has no built product path`);
    if (productPath && productPaths.has(productPath)) {
      errors.push(`product path ${productPath} is shared by ${productPaths.get(productPath)} and ${target.name}`);
    } else if (productPath) productPaths.set(productPath, target.name);
    const extension = productPath?.includes(".") ? productPath.slice(productPath.lastIndexOf(".") + 1) : "";
    if (productName && productPath && productPath !== `${productName}.${extension}`) {
      errors.push(`${target.name} product path ${productPath} does not match PRODUCT_NAME ${productName}`);
    }
    checkProduct(errors, target, configs, objects.get(target.productReference));
  }

  for (const key of WRAPPER_OVERRIDES) {
    if (project.includes(`${key} =`)) errors.push(`${key} must stay unset so outputs stay inside the product wrapper`);
  }
  const spec = readFileSync(join(root, "project.yml"), "utf8");
  const specLines = new Set(spec.split("\n").map((line) => line.trim()));
  for (const key of WRAPPER_OVERRIDES) {
    if (specLines.has(`${key}:`) || spec.includes(`${key}:`)) errors.push(`project.yml must not set ${key}`);
  }
  for (const line of ["ENABLE_DEBUG_DYLIB: NO", "ENABLE_PREVIEWS: NO"]) {
    const count = spec.split("\n").filter((row) => row.trim() === line).length;
    if (count !== 2) errors.push(`project.yml must set ${line} on the iOS app and the iOS extension`);
  }
  for (const product of Object.values(PRODUCTS)) {
    const productName = product.path.slice(0, product.path.lastIndexOf("."));
    if (!specLines.has(`PRODUCT_NAME: ${productName}`)) errors.push(`project.yml is missing PRODUCT_NAME ${productName}`);
  }
  const macApp = targets.find((target) => target.name === "Vigil macOS");
  const iosApp = targets.find((target) => target.name === "Vigil iOS");
  const macExtension = targets.find((target) => target.name === "Vigil macOS Extension");
  const iosExtension = targets.find((target) => target.name === "Vigil iOS Extension");
  if (!macApp || !iosApp || !macExtension || !iosExtension) errors.push("missing an app or extension target");
  if (macApp && macExtension && iosExtension) {
    checkEmbed(errors, objects, macApp, macExtension, iosExtension);
    checkBundlePrefix(errors, objects, macApp, macExtension);
  }
  if (iosApp && iosExtension && macExtension) {
    checkEmbed(errors, objects, iosApp, iosExtension, macExtension);
    checkBundlePrefix(errors, objects, iosApp, iosExtension);
  }
  checkPlist(errors, plist);
  checkSchemes(errors, root);
  if (iosExtension) checkIosResourceLayout(errors, objects, iosExtension);
  return errors;
}

function checkIosResourceLayout(errors, objects, iosExtension) {
  let copiesContents = false;
  for (const phaseId of iosExtension.buildPhases) {
    const phase = objects.get(phaseId);
    if (!phase) continue;
    if (phase.isa === "PBXResourcesBuildPhase") {
      for (const fileId of phase.files) {
        const buildFile = objects.get(fileId);
        const fileRef = idOf(setting(buildFile?.body ?? "", "fileRef"));
        const ref = fileRef ? objects.get(fileRef) : null;
        if (setting(ref?.body ?? "", "lastKnownFileType") === "folder") {
          errors.push("iOS extension must not copy a folder into the appex");
        }
      }
    }
    if (phase.isa === "PBXShellScriptBuildPhase" && phase.body.includes("Shared (Extension)/Resources/.")) {
      copiesContents = true;
    }
  }
  if (!copiesContents) errors.push("iOS extension must copy resource files into the appex root");
}

function checkProduct(errors, target, configs, product) {
  const expected = PRODUCTS[target.name];
  if (!expected) {
    errors.push(`unexpected target ${target.name}`);
    return;
  }
  if (target.productType !== expected.productType) errors.push(`${target.name} productType is ${target.productType ?? "missing"}`);
  const fileType = product ? setting(product.body, "explicitFileType") : null;
  const sourceTree = product ? setting(product.body, "sourceTree") : null;
  if (fileType !== expected.fileType) errors.push(`${target.name} explicitFileType is ${fileType ?? "missing"}`);
  if (sourceTree !== "BUILT_PRODUCTS_DIR") errors.push(`${target.name} product sourceTree must be BUILT_PRODUCTS_DIR`);
  for (const config of configs) {
    const label = `${target.name} ${config.name}`;
    if (setting(config.body, "SDKROOT") !== expected.sdk) errors.push(`${label} SDKROOT must be ${expected.sdk}`);
    if (setting(config.body, "PRODUCT_NAME") !== expected.path.slice(0, expected.path.lastIndexOf("."))) {
      errors.push(`${label} PRODUCT_NAME must match ${expected.path}`);
    }
    if (setting(config.body, "INFOPLIST_FILE") !== expected.infoPlist) errors.push(`${label} INFOPLIST_FILE must be ${expected.infoPlist}`);
    if (setting(config.body, "PRODUCT_BUNDLE_IDENTIFIER") !== expected.bundleId) errors.push(`${label} bundle id must be ${expected.bundleId}`);
    if (setting(config.body, "GENERATE_INFOPLIST_FILE") !== "NO") errors.push(`${label} GENERATE_INFOPLIST_FILE must be NO`);
    if (expected.sdk === "iphoneos") {
      if (setting(config.body, "ENABLE_DEBUG_DYLIB") !== "NO") {
        errors.push(`${label} ENABLE_DEBUG_DYLIB must be NO so the appex is not a debug dylib`);
      }
      if (setting(config.body, "ENABLE_PREVIEWS") !== "NO") {
        errors.push(`${label} ENABLE_PREVIEWS must be NO so the appex does not contain __preview.dylib`);
      }
    }
    for (const key of WRAPPER_OVERRIDES) {
      if (setting(config.body, key) !== null) errors.push(`${label} must not set ${key}`);
    }
    if (expected.platforms) {
      const platforms = (setting(config.body, "SUPPORTED_PLATFORMS") ?? "").split(/\s+/);
      for (const platform of expected.platforms) {
        if (!platforms.includes(platform)) errors.push(`${label} SUPPORTED_PLATFORMS must include ${platform}`);
      }
    } else if ((setting(config.body, "SUPPORTED_PLATFORMS") ?? "").includes("iphone")) {
      errors.push(`${label} must not list an iPhone platform`);
    }
  }
}

function checkEmbed(errors, objects, app, extension, otherExtension) {
  const embedded = [];
  for (const phaseId of app.buildPhases) {
    const phase = objects.get(phaseId);
    if (phase?.isa !== "PBXCopyFilesBuildPhase") continue;
    if (setting(phase.body, "dstSubfolderSpec") !== "13") errors.push(`${app.name} embed destination must be PlugIns`);
    embedded.push(...phase.files);
  }
  if (embedded.length !== 1) errors.push(`${app.name} embeds ${embedded.length} appex products`);
  const buildFile = embedded[0] ? objects.get(embedded[0]) : null;
  const fileRef = buildFile ? idOf(setting(buildFile.body, "fileRef")) : null;
  if (fileRef !== extension.productReference) errors.push(`${app.name} embed does not reference ${extension.name}`);
  if (otherExtension && fileRef === otherExtension.productReference) errors.push(`${app.name} embeds ${otherExtension.name}`);
  const dependencyTargets = app.dependencyIds.map((id) => idOf(setting(objects.get(id)?.body ?? "", "target")));
  if (!dependencyTargets.includes(extension.id)) errors.push(`${app.name} does not depend on ${extension.name}`);
  if (otherExtension && dependencyTargets.includes(otherExtension.id)) errors.push(`${app.name} depends on ${otherExtension.name}`);
}

function checkBundlePrefix(errors, objects, app, extension) {
  const appId = setting(configurations(objects, app)[0]?.body ?? "", "PRODUCT_BUNDLE_IDENTIFIER");
  for (const config of configurations(objects, extension)) {
    const extensionId = setting(config.body, "PRODUCT_BUNDLE_IDENTIFIER");
    if (!appId || !extensionId?.startsWith(`${appId}.`)) {
      errors.push(`${extension.name} bundle id ${extensionId ?? "missing"} must be prefixed by ${appId ?? "the app id"}`);
    }
  }
}

function checkPlist(errors, plist) {
  const executable = plistString(plist, "CFBundleExecutable");
  const packageType = plistString(plist, "CFBundlePackageType");
  const identifier = plistString(plist, "CFBundleIdentifier");
  const point = nestedString(plist, "NSExtension", "NSExtensionPointIdentifier");
  const principal = nestedString(plist, "NSExtension", "NSExtensionPrincipalClass");
  if (executable !== "$(EXECUTABLE_NAME)") errors.push(`CFBundleExecutable is ${executable ?? "missing"}`);
  if (packageType !== "XPC!") errors.push(`CFBundlePackageType is ${packageType ?? "missing"}`);
  if (identifier !== "$(PRODUCT_BUNDLE_IDENTIFIER)") errors.push("CFBundleIdentifier must track the product bundle id");
  if (point !== "com.apple.Safari.web-extension") errors.push(`NSExtensionPointIdentifier is ${point ?? "missing"}`);
  if (principal !== "$(PRODUCT_MODULE_NAME).SafariWebExtensionHandler") {
    errors.push(`NSExtensionPrincipalClass is ${principal ?? "missing"}`);
  }
}

function checkSchemes(errors, root) {
  const ios = readFileSync(join(root, "Vigil.xcodeproj/xcshareddata/xcschemes/Vigil iOS.xcscheme"), "utf8");
  const mac = readFileSync(join(root, "Vigil.xcodeproj/xcshareddata/xcschemes/Vigil macOS.xcscheme"), "utf8");
  if (!ios.includes('BuildableName = "VigilIOS.app"')) errors.push("iOS scheme must build VigilIOS.app");
  if (!mac.includes('BuildableName = "VigilMac.app"')) errors.push("macOS scheme must build VigilMac.app");
  if (ios.includes('BuildableName = "Vigil.app"') || mac.includes('BuildableName = "Vigil.app"')) {
    errors.push("a scheme still builds the shared Vigil.app product");
  }
}

function parseObjects(project) {
  const objects = new Map();
  const re = /\n\t\t([A-F0-9]{24}) \/\* (.*?) \*\/ = \{\n([\s\S]*?)\n\t\t\};/g;
  for (const match of project.matchAll(re)) {
    const body = match[3];
    const isa = body.match(/isa = ([A-Za-z]+);/)?.[1] ?? "";
    const entry = {
      id: match[1],
      comment: match[2],
      isa,
      body,
      name: setting(body, "name"),
      productType: setting(body, "productType"),
      productReference: idOf(setting(body, "productReference")),
      buildPhases: listIds(body, "buildPhases"),
      dependencyIds: listIds(body, "dependencies"),
      files: listIds(body, "files"),
    };
    objects.set(match[1], entry);
  }
  const oneLine = /^\t\t([A-F0-9]{24}) \/\* (.*?) \*\/ = \{([^\n]*)\};$/gm;
  for (const match of project.matchAll(oneLine)) {
    const body = match[3];
    const isa = body.match(/isa = ([A-Za-z]+);/)?.[1] ?? "";
    objects.set(match[1], {
      id: match[1],
      comment: match[2],
      isa,
      body,
      name: setting(body, "name"),
      productType: null,
      productReference: null,
      buildPhases: [],
      dependencyIds: [],
      files: [],
    });
  }
  return objects;
}

function configurations(objects, target) {
  const listId = idOf(setting(target.body, "buildConfigurationList"));
  const list = listId ? objects.get(listId) : null;
  if (!list) return [];
  return listIds(list.body, "buildConfigurations").map((id) => objects.get(id)).filter(Boolean);
}

function listIds(body, name) {
  const block = body.match(new RegExp(`\\n\\t\\t\\t${name} = \\(([\\s\\S]*?)\\n\\t\\t\\t\\);`));
  if (!block) return [];
  return [...block[1].matchAll(/([A-F0-9]{24})/g)].map((match) => match[1]);
}

function idOf(value) {
  return value?.match(/[A-F0-9]{24}/)?.[0] ?? null;
}

function setting(block, name) {
  const match = block.match(new RegExp(`(?:^|[\\n;])\\s*${name} = ([^;\\n]+);`));
  const value = match?.[1]?.trim() ?? null;
  if (value?.startsWith('"') && value.endsWith('"')) return value.slice(1, -1);
  return value;
}

function plistString(xml, key) {
  const match = xml.match(new RegExp(`<key>${key}</key>\\s*<string>([^<]*)</string>`));
  return match?.[1] ?? null;
}

function nestedString(xml, parent, key) {
  const parentMatch = xml.match(new RegExp(`<key>${parent}</key>\\s*<dict>([\\s\\S]*?)</dict>`));
  if (!parentMatch?.[1]) return null;
  return plistString(parentMatch[1], key);
}

const invoked = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
  const errors = checkIosExtension();
  if (errors.length > 0) {
    process.stderr.write(`${errors.join("\n")}\n`);
    process.exit(1);
  }
}
