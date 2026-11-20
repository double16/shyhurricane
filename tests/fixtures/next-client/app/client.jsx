"use client";

import dynamic from "next/dynamic";
import { useState } from "react";
import { preview } from "./actions";

const Lazy = dynamic(() => import("./lazy"), { ssr: false });

export default function Client() {
  const [label, setLabel] = useState("");
  const [show, setShow] = useState(false);
  return <>
    <button onClick={async () => setLabel(await preview("example"))}>Preview</button>
    <output>{label}</output>
    <button onClick={() => setShow(true)}>Show details</button>
    {show && <Lazy />}
  </>;
}
