import { OPENER_BLANK_EVENT, OPENER_BLANK_MESSAGE } from "./blank-guard.js";

document.addEventListener(OPENER_BLANK_EVENT, () => {
  void chrome.runtime.sendMessage({ type: OPENER_BLANK_MESSAGE });
});
