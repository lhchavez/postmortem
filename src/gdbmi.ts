export type GDBMIFrame = {
  level: string;
  func: string;
  addr: string;
  file: string;
  fullname?: string;
  line?: string;
  arch?: string;
};

export type GDBMIThread = {
  id: string;
  'target-id': string;
  frame: GDBMIFrame;
  state: 'stopped' | 'running';
};

export type GDBMIRecord =
  | {
      type: 'result';
      token?: number;
      record: any;
    }
  | {
      type: 'console-stream' | 'log-stream' | 'error-stream';
      payload: string;
    }
  | {
      type: 'notify-async';
      class: 'thread-selected';
      output: {
        id: string;
        frame: GDBMIFrame;
      };
    }
  | {
      type: 'notify-async';
      class:
        | 'thread-created'
        | 'thread-exited'
        | 'thread-group-added'
        | 'thread-group-removed'
        | 'thread-group-started'
        | 'thread-group-exited';
    }
  | {
      type: 'exec-async';
      class: 'running' | 'stopped';
    };

export type AssemblyInstructionRecord = {
  address: string;
  'func-name': string;
  offset: string;
  inst: string;
};

export type DataDisassembleRecord = {
  asm_insns: AssemblyInstructionRecord[];
};

export type DisassembleGraphRecord = {
  [address: string]: {
    edges: { type: 'unconditional' | 'fallthrough' | 'jump'; target: string }[];
    external_edges: { target: string }[];
    instructions: {
      address: string;
      bytes: number[];
      mnemonic: string;
      op: string;
    }[];
  };
};

export type ListRegisterValuesRecord = {
  'register-values': {
    number: string;
    value: string;
  }[];
};

export type FunctionRecord = {
  address: string;
  name: string;
};

export type RegisterNamesRecord = {
  'register-names': string[];
};

export type StackDumpRecord = {
  addr: string;
  'nr-bytes': string;
  'total-bytes': string;
  'next-row': string;
  'prev-row': string;
  'next-page': string;
  'prev-page': string;
  memory: {
    addr: string;
    data: string[];
  }[];
};

export type StackListFramesRecord = {
  stack: GDBMIFrame[];
};

export type ThreadInfoRecord = {
  'current-thread-id': string;
  threads: GDBMIThread[];
};
