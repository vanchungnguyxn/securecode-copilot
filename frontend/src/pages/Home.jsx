export default function Home({ navigate }) {
  return (
    <div className="home">
      <section className="hero" aria-label="Giới thiệu">
        <div className="hero-visual" aria-hidden>
          <div className="hero-mesh" />
          <div className="hero-gridline" />
          <div className="hero-plane">
            <div className="hero-window">
              <div className="hero-window-bar">
                <span /><span /><span />
                <em>scan · hybrid</em>
              </div>
              <pre className="hero-code">{`# vulnerable
q = f"SELECT * FROM users WHERE id={uid}"

# SecureCode Copilot
# CodeBERT  → SQLi · high
# CodeT5    → parameterized rewrite
cursor.execute(
  "SELECT * FROM users WHERE id=?",
  (uid,),
)`}</pre>
            </div>
          </div>
        </div>
        <div className="hero-copy">
          <p className="brand-lockup">SecureCode Copilot</p>
          <h1 className="hero-title">Bảo mật code trước khi ship.</h1>
          <p className="hero-sub">
            Fine-tune local phát hiện lỗ hổng, giải thích CWE, và đề xuất bản vá — sẵn sàng CI.
          </p>
          <div className="hero-cta">
            <button type="button" className="btn btn-primary" onClick={() => navigate("/app")}>
              Mở workspace
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => navigate("/app", { sample: "python" })}>
              Thử sample Python
            </button>
          </div>
        </div>
      </section>

      <section className="section section-how">
        <div className="section-kicker">Pipeline</div>
        <h2 className="section-title">Ba bước. Một dòng chảy.</h2>
        <p className="section-lead">Rule SAST bắt pattern quen thuộc. CodeBERT lọc báo sai. CodeT5 viết lại đoạn an toàn.</p>
        <ol className="how-list">
          <li>
            <span className="how-n">01</span>
            <div>
              <h3>Quét</h3>
              <p>File, ZIP, hoặc GitHub — Py, JS, Java, C/C++, C#, PHP.</p>
            </div>
          </li>
          <li>
            <span className="how-n">02</span>
            <div>
              <h3>Hybrid detect</h3>
              <p>Rules + CodeBERT ngưỡng Anti-FP để giảm báo ảo.</p>
            </div>
          </li>
          <li>
            <span className="how-n">03</span>
            <div>
              <h3>Explain &amp; Fix</h3>
              <p>CodeT5-LoRA sinh giải thích và patch; Apply fix một click.</p>
            </div>
          </li>
        </ol>
      </section>

      <section className="section section-langs">
        <div className="section-kicker">Coverage</div>
        <h2 className="section-title">Đa ngôn ngữ, cùng một Copilot.</h2>
        <p className="section-lead">Một workspace cho vibe-code lẫn codebase thật.</p>
        <ul className="lang-row">
          {["Python", "JavaScript", "Java", "C", "C++", "C#", "PHP"].map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </section>

      <section className="section section-end">
        <div className="end-panel">
          <div>
            <div className="section-kicker light">Ready</div>
            <h2 className="section-title on-dark">Sẵn sàng quét repo của bạn.</h2>
            <p className="section-lead on-dark">Chạy trên máy — RTX 3050 đủ train &amp; inference local, không bắt buộc cloud LLM.</p>
          </div>
          <button type="button" className="btn btn-lime" onClick={() => navigate("/app")}>
            Vào workspace
          </button>
        </div>
      </section>

      <footer className="site-foot">
        <span>SecureCode Copilot</span>
        <span>Detect · Explain · Fix · CI/SARIF</span>
      </footer>
    </div>
  );
}
