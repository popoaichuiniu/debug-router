// Copyright 2024 The Lynx Authors. All rights reserved.
// Licensed under the Apache License Version 2.0 that can be found in the
// LICENSE file in the root directory of this source tree.

const assert = require("assert");
const {
  InternalIpDetector,
} = require("../dist/cjs/src/utils/InternalIpDetector");
const { defaultLogger } = require("../dist/cjs/src/utils/logger");

function ipv4(interfaceName, address, overrides = {}) {
  return {
    interface: interfaceName,
    address,
    cidr: `${address}/24`,
    netmask: "255.255.255.0",
    internal: false,
    linkLocal: false,
    ...overrides,
  };
}

describe("InternalIpDetector", () => {
  it("selects en0 and rejects point-to-point and inactive macOS interfaces", () => {
    const output = [
      "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500",
      "        status: active",
      "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380",
      "en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500",
      "        status: inactive",
    ].join("\n");
    const interfaces = [
      ipv4("en0", "192.168.1.129"),
      ipv4("utun9", "192.168.7.163"),
      ipv4("en1", "10.0.0.2"),
    ];

    const metadata = InternalIpDetector.parseDarwinIfconfig(output);
    InternalIpDetector.applyMetadata(interfaces, metadata);

    assert.strictEqual(interfaces[0].physical, true);
    assert.strictEqual(interfaces[1].physical, false);
    assert.strictEqual(interfaces[2].physical, false);
    assert.strictEqual(
      InternalIpDetector.selectLanInterface(interfaces).address,
      "192.168.1.129",
    );
  });

  it("decodes Linux broadcast, loopback, point-to-point, and down flags", () => {
    assert.deepStrictEqual(InternalIpDetector.decodeLinuxFlags("0x1043"), [
      "UP",
      "BROADCAST",
      "RUNNING",
    ]);
    assert.deepStrictEqual(InternalIpDetector.decodeLinuxFlags("0x49"), [
      "UP",
      "LOOPBACK",
      "RUNNING",
    ]);
    assert.deepStrictEqual(InternalIpDetector.decodeLinuxFlags("0x51"), [
      "UP",
      "POINTOPOINT",
      "RUNNING",
    ]);
    assert.deepStrictEqual(InternalIpDetector.decodeLinuxFlags("0x2"), [
      "BROADCAST",
    ]);
  });

  it("uses Linux ip metadata to reject virtual, point-to-point, and down links", () => {
    const links = JSON.stringify([
      {
        ifname: "eth0",
        flags: ["BROADCAST", "UP", "RUNNING"],
        operstate: "UP",
        link_type: "ether",
      },
      {
        ifname: "veth0",
        flags: ["BROADCAST", "UP", "RUNNING"],
        operstate: "UP",
        link_type: "ether",
        linkinfo: { info_kind: "veth" },
      },
      {
        ifname: "ppp0",
        flags: ["POINTOPOINT", "UP", "RUNNING"],
        operstate: "UP",
      },
      {
        ifname: "eth1",
        flags: ["BROADCAST"],
        operstate: "DOWN",
        link_type: "ether",
      },
    ]);
    const interfaces = [
      ipv4("eth0", "192.168.1.10"),
      ipv4("veth0", "172.17.0.2"),
      ipv4("ppp0", "10.0.0.2"),
      ipv4("eth1", "192.168.2.10"),
    ];

    InternalIpDetector.applyMetadata(
      interfaces,
      InternalIpDetector.parseLinuxIpLink(links),
    );

    assert.strictEqual(
      InternalIpDetector.selectLanInterface(interfaces).interface,
      "eth0",
    );
  });

  it("keeps only connected physical Windows adapters", () => {
    const interfaces = [
      ipv4("Wi-Fi", "192.168.1.20"),
      ipv4("My VPN", "10.10.0.2"),
    ];
    const metadata = InternalIpDetector.parseWindowsPhysicalInterfaces(
      JSON.stringify([{ interface: "Wi-Fi", status: "Up" }]),
    );

    InternalIpDetector.applyMetadata(interfaces, metadata);

    assert.strictEqual(interfaces[0].physical, true);
    assert.strictEqual(interfaces[1].physical, false);
    assert.strictEqual(
      InternalIpDetector.selectLanInterface(interfaces).interface,
      "Wi-Fi",
    );
  });

  it("filters internal and link-local addresses and warns before taking the first", () => {
    const warnings = [];
    const originalWarn = defaultLogger.warn;
    defaultLogger.warn = (message) => warnings.push(message);
    try {
      const interfaces = [
        ipv4("lo0", "127.0.0.1", { internal: true, physical: true }),
        ipv4("en9", "169.254.1.2", {
          linkLocal: true,
          physical: true,
        }),
        ipv4("en0", "192.168.1.20", { physical: true }),
        ipv4("en1", "192.168.2.20", { physical: true }),
      ];

      assert.strictEqual(
        InternalIpDetector.selectLanInterface(interfaces).address,
        "192.168.1.20",
      );
      assert.strictEqual(warnings.length, 1);
      assert.match(warnings[0], /192\.168\.1\.20/);
      assert.match(warnings[0], /192\.168\.2\.20/);
    } finally {
      defaultLogger.warn = originalWarn;
    }
  });

  it("uses the interface-name fallback only to reject known virtual names", () => {
    const interfaces = [
      ipv4("en0", "192.168.1.20"),
      ipv4("utun9", "192.168.7.163"),
      ipv4("docker0", "172.17.0.1"),
    ];

    InternalIpDetector.annotateInterfacesByName(interfaces);

    assert.strictEqual(interfaces[0].physical, true);
    assert.strictEqual(interfaces[1].physical, false);
    assert.strictEqual(interfaces[2].physical, false);
    assert.strictEqual(interfaces[0].detectionMethod, "name-fallback");
  });

  it("throws an error containing all diagnostics when no candidate exists", () => {
    const interfaces = [
      ipv4("lo0", "127.0.0.1", { internal: true, physical: false }),
      ipv4("utun9", "192.168.7.163", { physical: false }),
    ];

    assert.throws(
      () => InternalIpDetector.selectLanInterface(interfaces, "test failure"),
      (error) =>
        error.message.includes("test failure") &&
        error.message.includes("127.0.0.1") &&
        error.message.includes("192.168.7.163"),
    );
  });

  it("accepts a valid explicit IPv4 and rejects an invalid host", async () => {
    const result = await InternalIpDetector.detectInternalIPv4("192.168.1.88");
    assert.strictEqual(result.selected.address, "192.168.1.88");
    assert.strictEqual(result.selected.source, "explicit-host");

    await assert.rejects(
      () => InternalIpDetector.detectInternalIPv4("example.com"),
      /must be a valid IPv4 address/,
    );
  });
});
