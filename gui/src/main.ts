import App from "./ui/App.svelte";
import { mount } from "svelte";

const target = document.getElementById("app");
if (!target) throw new Error("missing #app mount point");

const app = mount(App, { target });

export default app;
