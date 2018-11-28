#!/usr/bin/env node
const grpc = require("grpc");
const protoLoader = require("@grpc/proto-loader");
const path = require("path");
const _get = require("lodash.get");
//@ts-ignore
const vorpal = require("vorpal")();
const fs = require("fs");
const Table = require("easy-table");
const crypto = require("crypto");

function createRpcClient(protoPath, serviceName, port) {
  const packageDefinition = protoLoader.loadSync(protoPath, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });

  const proto = grpc.loadPackageDefinition(packageDefinition);

  const Client = _get(proto, serviceName);
  const wrapper = {};
  const client = new Client(port, grpc.credentials.createInsecure());
  for (let rpc of Object.keys(Client.service)) {
    wrapper[rpc] = function(params = {}) {
      return new Promise((ok, fail) => {
        client[rpc](params, (error, result) => {
          if (error) return fail(error);
          ok(result);
        });
      });
    };
  }

  return wrapper;
}

function handleAction(actionFn) {
  return function(args, cb) {
    const path_ = args.options.c || "kms-cli.json";
    let cfg = {};
    try {
      const content = fs.readFileSync(path_);
      cfg = JSON.parse(content.toString());
    } catch (e) {
      vorpal.log(`Read config ${path_} failed: ${e.message}`);
      process.exit(1);
    }

    const server = args.options.s || cfg.server || "127.0.0.1:5000";
    const client = createRpcClient(
      path.resolve(__dirname, "kms.proto"),
      "Kms",
      server
    );

    args.tokens = cfg.tokens || {};
    args.client = client;

    actionFn
      .bind(this)(args)
      .then(cb)
      .catch(e => {
        this.log("Error:", e.message);
        cb();
      });
  };
}

function readFileBuffer(ifile) {
  try {
    return fs.readFileSync(ifile);
  } catch (e) {
    vorpal.log(`Read file ${ifile} failed: ${e.message}`);
    process.exit(1);
  }
}

function SafeBase64(buf) {
  const str = buf.toString("base64");
  return str
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function RandomToken(size) {
  const token = crypto.randomBytes(size).toString("base64");
  return SafeBase64(token);
}

function logTable(result, tableDef, filterFn) {
  if (result.error) {
    vorpal.log(result.error);
    return;
  }
  const t = new Table();

  const keys = Object.keys(tableDef);

  result.data.forEach(item => {
    if (filterFn && !filterFn(item)) {
      return;
    }

    for (let k of keys) {
      t.cell(tableDef[k], item[k]);
    }
    t.newRow();
  });
  vorpal.log(t.toString());
  vorpal.log(`${result.data.length} items`);
  return;
}

function logCrypto(result, ofile) {
  if (result.error) {
    vorpal.log(result.error);
    return;
  }

  if (ofile) {
    try {
      fs.writeFileSync(ofile, result.data);
    } catch (e) {
      vorpal.log(`Write file ${ofile} failed: ${e.message}`);
    }
  } else {
    const done = process.stdout.write(result.data);
    if (!done) {
      // this effectively means "wait for this
      // event to fire", but it doesn't block everything
      process.stdout.on("drain", () => 1);
    }
  }
}

function logCryptoHex(result) {
  if (result.error) {
    vorpal.log(result.error);
    return;
  }
  vorpal.log(result.data.toString("hex"));
}

function logTx(result, message) {
  if (result.error) {
    vorpal.log(result.error);
  } else {
    vorpal.log(message);
  }
}

function main() {
  vorpal
    .command("ns list", "List namespace")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .option("-a", "List disabled namespace")
    .action(
      handleAction(async function(args) {
        const sender = args.tokens.root;
        if (!sender) {
          this.log("Missing root token in config");
          return;
        }
        const result = await args.client.ListNS({ sender });

        logTable(
          result,
          {
            name: "Name",
            active: "Active"
          },
          item => (args.options.a ? true : item.active)
        );
      })
    );

  vorpal
    .command("ns create <name>", "New namespace")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const sender = args.tokens.root;
        if (!sender) {
          this.log("Missing root token in config");
          return;
        }
        const ns = args.name;
        const token = RandomToken(16);
        const result = await args.client.NewNS({
          sender,
          ns,
          token
        });
        logTx(result, `Access token: ${token}`);
      })
    );

  vorpal
    .command("ns reset <name>", "Reset namespace token")
    .option("-d", "Disable namespace")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const sender = args.tokens.root;
        if (!sender) {
          this.log("Missing root token in config");
          return;
        }

        const ns = args.name;
        const token = args.options.d ? "" : RandomToken(16);
        const result = await args.client.ResetNS({ sender, ns, token });
        logTx(
          result,
          args.options.d ? "Namespace disabled" : `Access token: ${token}`
        );
      })
    );

  vorpal
    .command("key list <ns>", "List key in a namespace")
    .option("-a", "List disabled keys")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const result = await args.client.ListKey({ sender, ns });

        logTable(
          result,
          {
            name: "Name",
            type: "Type",
            active: "Active"
          },
          item => (args.options.a ? true : item.active)
        );
      })
    );

  vorpal
    .command("key create <ns> <name> <type>", "Create key in a namespace")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const key = args.name;
        const type = args.type;
        const token = RandomToken(16);
        const result = await args.client.NewKey({
          sender,
          ns,
          key,
          type,
          token
        });
        logTx(result, `Access token: ${token}`);
      })
    );

  vorpal
    .command(
      "key import <ns> <name> <type> <keyfile>",
      "Import key (pem format) into a namespace"
    )
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const key = args.name;
        const type = args.type;
        const keyval = readFileBuffer(args.keyfile).toString();
        const token = RandomToken(16);
        const result = await args.client.ImportKey({
          sender,
          ns,
          key,
          type,
          keyval,
          token
        });

        logTx(result, `Access token: ${token}`);
      })
    );

  vorpal
    .command("key reset <ns> <name>", "Reset key token")
    .option("-d", "Disable key")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const key = args.name;
        const token = args.options.d ? "" : RandomToken(16);
        const result = await args.client.ResetKey({ sender, ns, key, token });

        logTx(
          result,
          args.options.d ? "Namespace disabled" : `Access token: ${token}`
        );
      })
    );

  vorpal
    .command("secret list <ns>", "List secrets in a namespace")
    .option("-a", "List disabled secrets")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const result = await args.client.ListSecret({ sender, ns });

        logTable(
          result,
          {
            name: "Name",
            active: "Active"
          },
          item => (args.options.a ? true : item.active)
        );
      })
    );

  vorpal
    .command("secret create <ns> <name> <secret>", "Create new secret")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const key = args.name;
        const token = RandomToken(16);
        const secret = readFileBuffer(args.secret);
        const result = await args.client.NewSecret({
          sender,
          ns,
          key,
          token,
          secret: secret.toString()
        });

        logTx(result, `Access token: ${token}`);
      })
    );

  vorpal
    .command("secret reset <ns> <name>", "Reset secret token")
    .option("-d", "Disable secret")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const sender = _get(args.tokens, ["namespaces", ns]);
        if (!sender) {
          this.log(`Missing namespace token of ${ns} in config`);
          return;
        }

        const key = args.name;
        const token = args.options.d ? "" : RandomToken(16);
        const result = await args.client.ResetSecret({
          sender,
          ns,
          key,
          token
        });

        logTx(
          result,
          args.options.d ? "Namespace disabled" : `Access token: ${token}`
        );
      })
    );

  vorpal
    .command("encrypt <ns> <key> <file>", "Encrypt a file")
    .option("-o <output file>", "Output file")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["keys", ns, key]);
        if (!sender) {
          this.log(`Missing key token of ${ns}.${key} in config`);
          return;
        }

        const text = readFileBuffer(args.file);

        const result = await args.client.Encrypt({ sender, ns, key, text });
        logCrypto(result, args.options.o);
      })
    );

  vorpal
    .command("decrypt <ns> <key> <file>", "Decrypt a file")
    .option("-o <output file>", "Output file")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["keys", ns, key]);
        if (!sender) {
          this.log(`Missing key token of ${ns}.${key} in config`);
          return;
        }

        const cipher = readFileBuffer(args.file);

        const result = await args.client.Decrypt({ sender, ns, key, cipher });
        logCrypto(result, args.options.o);
      })
    );

  vorpal
    .command("hmac <ns> <key> <file>", "Calculate hmac a file")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["keys", ns, key]);
        if (!sender) {
          this.log(`Missing key token of ${ns}.${key} in config`);
          return;
        }

        const text = readFileBuffer(args.file);

        const result = await args.client.Hmac({ sender, ns, key, text });
        logCryptoHex(result);
      })
    );

  vorpal
    .command("sign <ns> <key> <hash>", "Calculate signature of a hash")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .option("-o <output file>", "Output file")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["keys", ns, key]);
        if (!sender) {
          this.log(`Missing key token of ${ns}.${key} in config`);
          return;
        }

        const hash = Buffer.from(args.hash, "hex");
        const result = await args.client.Sign({ sender, ns, key, hash });
        logCrypto(result, args.options.o);
      })
    );

  vorpal
    .command(
      "verify <ns> <key> <hash> <signature>",
      "Verify signature of a hash"
    )
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["keys", ns, key]);
        if (!sender) {
          this.log(`Missing key token of ${ns}.${key} in config`);
          return;
        }

        const hash = Buffer.from(args.hash, "hex");
        const signature = readFileBuffer(args.signature);
        const result = await args.client.Verify({
          sender,
          ns,
          key,
          hash,
          signature
        });
        if (result.error) {
          vorpal.log(result.error);
          return;
        }

        if (result.data) {
          vorpal.log("true");
        } else {
          vorpal.log("false");
        }
      })
    );

  vorpal
    .command("get-secret <ns> <key>", "Read secret from namespace")
    .option("-c <config file>", "Config file")
    .option("-s <server>", "Kms server [name:port]")
    .action(
      handleAction(async function(args) {
        const ns = args.ns;
        const key = args.key;
        const sender = _get(args.tokens, ["secrets", ns, key]);
        if (!sender) {
          this.log(`Missing secret token of ${ns}.${key} in config`);
          return;
        }

        const result = await args.client.GetSecret({
          sender,
          ns,
          key
        });
        if (result.error) {
          vorpal.log(result.error);
          return;
        }

        process.stdout.write(result.data);
      })
    );

  vorpal.parse(process.argv);
}

main();
