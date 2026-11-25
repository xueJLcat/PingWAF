import type { DocsContent } from "../schema";

const docs = {
  meta: {
    title: "Documentation — PingWAF",
    description:
      "Architecture, deployment, the WAF engine and the REST/gRPC API: the seven documents you need to run PingWAF in production.",
  },
  hero: {
    eyebrow: "Documentation",
    title: "The seven documents that explain PingWAF",
    lead: "Start with the architecture if you are evaluating, deployment if you are installing, and the WAF engine if you are tuning rules.",
  },
  cards: [
    {
      slug: "architecture",
      icon: "network",
      title: "Architecture",
      lead: "How the control plane and data plane fit together, and what the gRPC protocol carries.",
      minutes: 8,
      topics: ["control plane", "data plane", "gRPC", "run modes"],
    },
    {
      slug: "deployment",
      icon: "server",
      title: "Deployment",
      lead: "All-in-one versus distributed, Docker and systemd, ports, configuration precedence.",
      minutes: 10,
      topics: ["docker", "systemd", "ports", "environment"],
    },
    {
      slug: "tunnel",
      icon: "route",
      title: "Tunnels",
      lead: "Serve an internal service through the WAF without an inbound port: pairing, the edge listener, pool binding, SOCKS5 egress and operations.",
      minutes: 12,
      topics: ['pairing', 'edge listener', 'SOCKS5', 'NAT'],
    },
    {
      slug: "waf-engine",
      icon: "shield",
      title: "WAF engine",
      lead: "The four-phase pipeline, expression rules, verdicts and the challenge flow.",
      minutes: 9,
      topics: ["pipeline", "expressions", "verdicts", "challenges"],
    },
    {
      slug: "waf-test-report",
      icon: "activity",
      title: "WAF test report",
      lead: "Measured effectiveness on the blazehttp corpus: interception, false positives, regression and determinism.",
      minutes: 10,
      topics: ["interception", "false positives", "regression", "p95"],
    },
    {
      slug: "api",
      icon: "code",
      title: "API",
      lead: "REST endpoints for automation, the gRPC contract for agents, and authentication.",
      minutes: 7,
      topics: ["REST", "gRPC", "auth", "automation"],
    },
    {
      slug: "security",
      icon: "lock",
      title: "Security",
      lead: "Report vulnerabilities privately, see which versions receive fixes, and harden an instance before exposure.",
      minutes: 8,
      topics: ["disclosure", "supported versions", "hardening", "secrets"],
    },
  ],
  sidebarLabel: "Documentation",
  screenshot: {
    key: "configVersions",
    url: "localhost:9080/config-versions",
    caption: "Every policy change is a version you can diff and roll back.",
    alt: "Configuration versions list with diffs and rollback actions",
  },
  github: {
    title: "The full documentation lives in the repository",
    body: "Quick start walkthrough, user guide, HTTP lifecycle, ACME details, benchmarking and security policy — all versioned next to the code.",
    link: { label: "Browse docs on GitHub", path: "https://github.com/shuaiZend/PingWAF/tree/main/docs" },
  },
  backToHub: "All documents",
  editLabel: "Edit this page on GitHub",
};

export default docs;
