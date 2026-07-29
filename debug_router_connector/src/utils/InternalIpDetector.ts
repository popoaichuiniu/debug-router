// Copyright 2024 The Lynx Authors. All rights reserved.
// Licensed under the Apache License Version 2.0 that can be found in the
// LICENSE file in the root directory of this source tree.

import { execFileSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { isIP } from "net";
import { networkInterfaces, NetworkInterfaceInfo } from "os";
import { defaultLogger } from "./logger";

type DetectionMethod =
  | "darwin-ifconfig"
  | "linux-sysfs"
  | "linux-ip"
  | "windows-powershell"
  | "name-fallback";

type InterfaceMetadata = {
  flags?: string[];
  status?: string;
  physical: boolean;
  detectionMethod: DetectionMethod;
};

type LinuxIpLink = {
  ifname?: string;
  flags?: string[];
  operstate?: string;
  link_type?: string;
  linkinfo?: {
    info_kind?: string;
  };
};

type WindowsPhysicalInterface = {
  interface?: string;
  status?: string;
};

export type IPv4Interface = {
  /** Operating-system network interface name, such as en0 or lo0. */
  interface: string;
  /** IPv4 address assigned to this interface. */
  address: string;
  /** IPv4 address and network prefix, such as 192.168.1.10/24. */
  cidr: string;
  /** Subnet mask associated with the IPv4 address. */
  netmask: string;
  /** Whether Node.js identifies this as an internal/loopback address. */
  internal: boolean;
  /** Whether this address belongs to the link-local 169.254.0.0/16 range. */
  linkLocal: boolean;
  /** Operating-system interface flags used during LAN eligibility checks. */
  flags?: string[];
  /** Operating-system link state, such as active, up, or connected. */
  status?: string;
  /** Whether platform inspection classified this as an active physical LAN. */
  physical?: boolean;
  /** Platform inspection or fallback method used for this interface. */
  detectionMethod?: DetectionMethod;
};

export type InternalIpDetectionResult = {
  selected: {
    address: string;
    interface?: string;
    source: "explicit-host" | "lan-interface";
  };
  interfaces: IPv4Interface[];
};

const REQUIRED_LAN_FLAGS = ["UP", "BROADCAST", "RUNNING"];
const DISALLOWED_LAN_FLAGS = ["LOOPBACK", "POINTOPOINT"];
const VIRTUAL_INTERFACE_NAME = /^(?:utun|tun|tap|ppp|wg|tailscale|wireguard|wintun|vpn|docker|veth|br-)/i;
const VIRTUAL_LINUX_KINDS = new Set([
  "bridge",
  "docker",
  "dummy",
  "geneve",
  "gre",
  "gretap",
  "ifb",
  "ip6gre",
  "ip6tnl",
  "ipip",
  "macvlan",
  "macvtap",
  "sit",
  "tap",
  "tun",
  "veth",
  "vlan",
  "vrf",
  "vxlan",
  "wireguard",
]);

const IFF_UP = 0x1;
const IFF_BROADCAST = 0x2;
const IFF_LOOPBACK = 0x8;
const IFF_POINTOPOINT = 0x10;
const IFF_RUNNING = 0x40;

export class InternalIpDetector {
  static async detectInternalIPv4(
    explicitHost?: string,
  ): Promise<InternalIpDetectionResult> {
    const interfaces = this.getIPv4Interfaces();

    if (explicitHost !== undefined) {
      if (isIP(explicitHost) !== 4) {
        throw new Error(
          `websocketOption.host must be a valid IPv4 address: ${explicitHost}`,
        );
      }

      return {
        selected: {
          address: explicitHost,
          interface: interfaces.find((item) => item.address === explicitHost)
            ?.interface,
          source: "explicit-host",
        },
        interfaces,
      };
    }

    let inspectionError: string | undefined;
    try {
      this.annotateInterfacesForPlatform(interfaces);
    } catch (error) {
      inspectionError = (error as Error).message;
      defaultLogger.warn(
        `[internal-ip] Platform interface inspection failed; using interface-name fallback: ${inspectionError}`,
      );
      this.annotateInterfacesByName(interfaces);
    }

    const selected = this.selectLanInterface(interfaces, inspectionError);

    return {
      selected: {
        address: selected.address,
        interface: selected.interface,
        source: "lan-interface",
      },
      interfaces,
    };
  }

  private static getIPv4Interfaces(): IPv4Interface[] {
    const result: IPv4Interface[] = [];

    for (const [name, addresses] of Object.entries(networkInterfaces())) {
      for (const item of addresses ?? []) {
        if (!this.isIPv4(item)) {
          continue;
        }

        result.push({
          interface: name,
          address: item.address,
          cidr: item.cidr ?? "",
          netmask: item.netmask,
          internal: item.internal,
          linkLocal: this.isLinkLocalIPv4(item.address),
        });
      }
    }

    return result;
  }

  private static isIPv4(item: NetworkInterfaceInfo): boolean {
    return item.family === "IPv4" || (item.family as unknown) === 4;
  }

  private static isLinkLocalIPv4(address: string): boolean {
    return address.startsWith("169.254.");
  }

  private static annotateInterfacesForPlatform(
    interfaces: IPv4Interface[],
  ): void {
    switch (process.platform) {
      case "darwin":
        this.applyMetadata(interfaces, this.inspectDarwinInterfaces());
        return;
      case "linux":
        this.inspectLinuxInterfaces(interfaces);
        return;
      case "win32":
        this.applyMetadata(interfaces, this.inspectWindowsInterfaces());
        return;
      default:
        throw new Error(`Unsupported platform: ${process.platform}`);
    }
  }

  private static inspectDarwinInterfaces(): Map<string, InterfaceMetadata> {
    const output = execFileSync("/sbin/ifconfig", ["-a"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 5000,
    });
    const metadata = this.parseDarwinIfconfig(output);
    if (metadata.size === 0) {
      throw new Error("/sbin/ifconfig returned no recognizable interfaces");
    }
    return metadata;
  }

  private static parseDarwinIfconfig(
    output: string,
  ): Map<string, InterfaceMetadata> {
    const metadata = new Map<string, InterfaceMetadata>();
    let currentName: string | undefined;

    for (const line of output.split(/\r?\n/)) {
      const header = /^([^\s:]+):\s+flags=\d+<([^>]*)>/.exec(line);
      if (header) {
        currentName = header[1];
        const flags = header[2]
          .split(",")
          .map((flag) => flag.trim().toUpperCase())
          .filter(Boolean);
        metadata.set(currentName, {
          flags,
          physical: this.hasLanFlags(flags),
          detectionMethod: "darwin-ifconfig",
        });
        continue;
      }

      const status = /^\s*status:\s*(\S+)/i.exec(line);
      if (currentName && status) {
        const item = metadata.get(currentName);
        if (item) {
          item.status = status[1].toLowerCase();
          item.physical = item.physical && item.status !== "inactive";
        }
      }
    }

    return metadata;
  }

  private static inspectLinuxInterfaces(interfaces: IPv4Interface[]): void {
    try {
      const metadata = new Map<string, InterfaceMetadata>();
      for (const name of new Set(interfaces.map((item) => item.interface))) {
        const flagsPath = `/sys/class/net/${name}/flags`;
        const rawFlags = readFileSync(flagsPath, "utf8").trim();
        const flags = this.decodeLinuxFlags(rawFlags);
        const hasDevice = existsSync(`/sys/class/net/${name}/device`);
        metadata.set(name, {
          flags,
          status: flags.includes("RUNNING") ? "up" : "down",
          physical: this.hasLanFlags(flags) && hasDevice,
          detectionMethod: "linux-sysfs",
        });
      }
      this.applyMetadata(interfaces, metadata);
      return;
    } catch (sysfsError) {
      try {
        const output = execFileSync("ip", ["-json", "link", "show"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 5000,
        });
        this.applyMetadata(interfaces, this.parseLinuxIpLink(output));
        return;
      } catch (ipError) {
        throw new Error(
          `Linux interface inspection failed (sysfs: ${
            (sysfsError as Error).message
          }; ip: ${(ipError as Error).message})`,
        );
      }
    }
  }

  private static decodeLinuxFlags(rawFlags: string): string[] {
    const value = Number.parseInt(rawFlags, 0);
    if (!Number.isFinite(value)) {
      throw new Error(`Invalid Linux interface flags: ${rawFlags}`);
    }

    const flags: string[] = [];
    if ((value & IFF_UP) !== 0) flags.push("UP");
    if ((value & IFF_BROADCAST) !== 0) flags.push("BROADCAST");
    if ((value & IFF_LOOPBACK) !== 0) flags.push("LOOPBACK");
    if ((value & IFF_POINTOPOINT) !== 0) flags.push("POINTOPOINT");
    if ((value & IFF_RUNNING) !== 0) flags.push("RUNNING");
    return flags;
  }

  private static parseLinuxIpLink(
    output: string,
  ): Map<string, InterfaceMetadata> {
    const links = JSON.parse(output) as LinuxIpLink[];
    const metadata = new Map<string, InterfaceMetadata>();

    for (const link of links) {
      if (!link.ifname) continue;
      const flags = (link.flags ?? []).map((flag) => flag.toUpperCase());
      const status = (link.operstate ?? "unknown").toLowerCase();
      const kind = link.linkinfo?.info_kind?.toLowerCase();
      const virtual = kind !== undefined && VIRTUAL_LINUX_KINDS.has(kind);
      metadata.set(link.ifname, {
        flags,
        status,
        physical:
          this.hasLanFlags(flags) &&
          status === "up" &&
          link.link_type === "ether" &&
          !virtual,
        detectionMethod: "linux-ip",
      });
    }

    if (metadata.size === 0) {
      throw new Error("ip -json link show returned no recognizable interfaces");
    }
    return metadata;
  }

  private static inspectWindowsInterfaces(): Map<string, InterfaceMetadata> {
    const script = [
      "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
      "$connected = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.ConnectionState -eq 'Connected' } | Select-Object -ExpandProperty InterfaceIndex)",
      "$records = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $connected -contains $_.InterfaceIndex } | ForEach-Object { [PSCustomObject]@{ interface = $_.Name; status = $_.Status } })",
      "ConvertTo-Json -InputObject $records -Compress",
    ].join("; ");
    const output = execFileSync(
      "powershell.exe",
      [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
      ],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 5000,
      },
    );
    return this.parseWindowsPhysicalInterfaces(output);
  }

  private static parseWindowsPhysicalInterfaces(
    output: string,
  ): Map<string, InterfaceMetadata> {
    const parsed = JSON.parse(output.trim() || "[]") as
      | WindowsPhysicalInterface
      | WindowsPhysicalInterface[];
    const records = Array.isArray(parsed) ? parsed : [parsed];
    const metadata = new Map<string, InterfaceMetadata>();

    for (const record of records) {
      if (!record.interface) continue;
      metadata.set(record.interface, {
        flags: ["UP", "BROADCAST", "RUNNING"],
        status: (record.status ?? "connected").toLowerCase(),
        physical: true,
        detectionMethod: "windows-powershell",
      });
    }

    return metadata;
  }

  private static hasLanFlags(flags: string[]): boolean {
    return (
      REQUIRED_LAN_FLAGS.every((flag) => flags.includes(flag)) &&
      DISALLOWED_LAN_FLAGS.every((flag) => !flags.includes(flag))
    );
  }

  private static selectLanInterface(
    interfaces: IPv4Interface[],
    inspectionError?: string,
  ): IPv4Interface {
    const candidates = interfaces.filter(
      (item) => !item.internal && !item.linkLocal && item.physical === true,
    );

    if (candidates.length > 1) {
      defaultLogger.warn(
        `[internal-ip] Multiple LAN IPv4 interfaces found; selecting the first candidate: ${JSON.stringify(
          candidates,
          null,
          2,
        )}`,
      );
    }

    const selected = candidates[0];
    if (selected) {
      return selected;
    }

    const inspection = inspectionError
      ? ` Platform inspection error: ${inspectionError}.`
      : "";
    throw new Error(
      `[internal-ip] No active physical LAN IPv4 interface is available.${inspection} Interfaces: ${JSON.stringify(
        interfaces,
        null,
        2,
      )}`,
    );
  }

  private static applyMetadata(
    interfaces: IPv4Interface[],
    metadata: Map<string, InterfaceMetadata>,
  ): void {
    for (const item of interfaces) {
      const info = metadata.get(item.interface);
      item.flags = info?.flags;
      item.status = info?.status;
      item.physical = info?.physical ?? false;
      item.detectionMethod = info?.detectionMethod;
    }
  }

  private static annotateInterfacesByName(interfaces: IPv4Interface[]): void {
    for (const item of interfaces) {
      item.physical =
        !item.internal &&
        !item.linkLocal &&
        !VIRTUAL_INTERFACE_NAME.test(item.interface);
      item.detectionMethod = "name-fallback";
    }
  }
}
