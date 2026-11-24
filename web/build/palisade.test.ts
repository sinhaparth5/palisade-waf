import { leftovers, localRules, sharedRules, unbrander } from "./palisade.ts";

describe("unbrand", () => {
  it("renames shared names the same way in JS (either quote style) and CSS", () => {
    const u = unbrander(sharedRules);
    expect(u.apply('e.__reactFiber$x=1;e._reactRootContainer;e.$$reactFormReplay;Symbol.for("react.element");"data-sonner-toast"')).toBe(
      'e.__plFiber$x=1;e._plRootContainer;e.$$plFormReplay;Symbol.for("pl.element");"data-pltoast-toast"',
    );
    expect(u.apply("Symbol.for(`react.element`)")).toBe("Symbol.for(`pl.element`)");
    expect(u.apply("[data-sonner-toast]{}[data-slot=card]{}")).toBe("[data-pltoast-toast]{}[data-part=card]{}");
    expect(u.apply('if (typeof self !== "undefined") self.__TSR_ROUTER__ = this;')).toBe('if (typeof self !== "undefined") 0;');
  });

  it("rewrites React's minified error message", () => {
    const u = unbrander(localRules);
    const src = "t=`https://react.dev/errors/`+e;return`Minified React error #`+e+`; visit `+t+` for the full message or use the non-minified dev environment for full errors and additional helpful warnings.`";
    expect(u.apply(src)).toBe("t=``+e;return`Error #`+e+``");
  });

  it("reports a rule that never matched and a name nothing renamed", () => {
    const u = unbrander([[/__vite__mapDeps/g, "x"]]);
    u.apply("window.__TANSTACK_DEVTOOLS__=1");
    expect(u.dead()).toEqual(["__vite__mapDeps"]);
    expect(leftovers(["window.__TANSTACK_DEVTOOLS__=1", "ok"])).toEqual(["__TANSTACK_DEVTOOLS__"]);
  });
});
