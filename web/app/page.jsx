import dynamic from "next/dynamic";

const Dashboard = dynamic(() => import("../components/Dashboard"), {
  ssr: false,
  loading: () => (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "#F1F2F4",
      fontFamily: "system-ui, -apple-system, sans-serif",
    }}>
      <p style={{ color: "#A1A1AA" }}>Loading...</p>
    </div>
  ),
});

export default function Home() {
  return <Dashboard />;
}