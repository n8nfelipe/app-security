import { expect, test, vi } from "vitest";

import * as api from "./api";

test("api exports all required methods", () => {
  expect(api.api.listUsers).toBeDefined();
  expect(api.api.listContainers).toBeDefined();
  expect(api.api.listNetworkDevices).toBeDefined();
  expect(api.api.listRules).toBeDefined();
  expect(api.api.createScan).toBeDefined();
  expect(api.api.scanStatus).toBeDefined();
  expect(api.api.scanResults).toBeDefined();
  expect(api.api.history).toBeDefined();
  expect(api.api.exportJson).toBeDefined();
  expect(api.api.exportPdf).toBeDefined();
});

test("listUsers is a function", () => {
  expect(typeof api.api.listUsers).toBe("function");
});

test("listContainers is a function", () => {
  expect(typeof api.api.listContainers).toBe("function");
});

test("history is a function", () => {
  expect(typeof api.api.history).toBe("function");
});

test("createScan is a function", () => {
  expect(typeof api.api.createScan).toBe("function");
});

test("exportJson is a function", () => {
  expect(typeof api.api.exportJson).toBe("function");
});

test("exportPdf is a function", () => {
  expect(typeof api.api.exportPdf).toBe("function");
});

test("scanStatus is a function", () => {
  expect(typeof api.api.scanStatus).toBe("function");
});

test("scanResults is a function", () => {
  expect(typeof api.api.scanResults).toBe("function");
});

test("listNetworkDevices is a function", () => {
  expect(typeof api.api.listNetworkDevices).toBe("function");
});

test("listRules is a function", () => {
  expect(typeof api.api.listRules).toBe("function");
});