import Link from "next/link";
import Client from "./client";
import { save } from "./actions";

export default function Page() {
  return <>
    <Link href="/items/example">Example item</Link>
    <form action={save}><input name="label" /><button>Save</button></form>
    <Client />
  </>;
}
