import { existsSync, readFileSync } from "node:fs";
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
  "Vigil macOS Extension": {
    productType: "com.apple.product-type.app-extension",
    fileType: "wrapper.app-extension",
    path: "VigilMacExtension.appex",
    sdk: "macosx",
    infoPlist: "macOS (Extension)/Info.plist",
    bundleId: "com.example.vigil.macos.extension",
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
  const plist = readFileSync(join(root, "macOS (Extension)/Info.plist"), "utf8");
  for (const rel of ["iOS (App)", "iOS (Extension)", "Vigil.xcodeproj/xcshareddata/xcschemes/Vigil iOS.xcscheme"]) {
    if (existsSync(join(root, rel))) errors.push(`${rel} must stay out of this release`);
  }
  const objects = parseObjects(project);
  const targets = [...objects.values()].filter((item) => item.isa === "PBXNativeTarget");
  if (targets.length !== 3) errors.push(`expected 3 native targets, found ${targets.length}`);
  if (project.includes("iphoneos") || project.includes("VigilIOS") || targets.some((target) => target.name?.includes("iOS"))) {
    errors.push("this release must not include an iOS target");
  }

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
  if (spec.includes("Vigil iOS") || spec.includes("com.example.vigil.ios")) {
    errors.push("project.yml must not describe an iOS target");
  }
  for (const product of Object.values(PRODUCTS)) {
    const productName = product.path.slice(0, product.path.lastIndexOf("."));
    if (!specLines.has(`PRODUCT_NAME: ${productName}`)) errors.push(`project.yml is missing PRODUCT_NAME ${productName}`);
  }
  const macApp = targets.find((target) => target.name === "Vigil macOS");
  const macExtension = targets.find((target) => target.name === "Vigil macOS Extension");
  if (!macApp || !macExtension) errors.push("missing the macOS app or extension target");
  if (macApp && macExtension) {
    checkEmbed(errors, objects, macApp, macExtension, null);
    checkBundlePrefix(errors, objects, macApp, macExtension);
  }
  checkPlist(errors, plist);
  checkSchemes(errors, root);
  return errors;
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
  const mac = readFileSync(join(root, "Vigil.xcodeproj/xcshareddata/xcschemes/Vigil macOS.xcscheme"), "utf8");
  if (!mac.includes('BuildableName = "VigilMac.app"')) errors.push("macOS scheme must build VigilMac.app");
  if (mac.includes('BuildableName = "Vigil.app"') || mac.includes("VigilIOS")) {
    errors.push("the macOS scheme must build only the macOS app");
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
