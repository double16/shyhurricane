import Link from "next/link";

export default function Item({ id }) {
  return <><p>{id}</p><Link href="/">Home</Link></>;
}

export async function getStaticPaths() {
  return { paths: [{ params: { id: "example" } }], fallback: false };
}

export async function getStaticProps({ params }) {
  return { props: { id: params.id } };
}
