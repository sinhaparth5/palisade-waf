// jsdom has no EventSource. FakeEventSource records every stream the app
// opens; a test pushes server events with FakeEventSource.last!.emit(...).
export class FakeEventSource extends EventTarget {
  static all: FakeEventSource[] = [];
  static get last() {
    return FakeEventSource.all.at(-1);
  }
  closed = false;
  constructor(readonly url: string) {
    super();
    FakeEventSource.all.push(this);
  }
  close() {
    this.closed = true;
  }
  emit(type: string, data: string) {
    this.dispatchEvent(new MessageEvent(type, { data }));
  }
}
