"""Generate Review-3 slides as Beamer LaTeX (slides.tex) and PowerPoint (slides.pptx) from one spec."""
import re
import sys
from pathlib import Path

OUT = Path(sys.argv[1])

# ------------------------------------------------------------------ content
# Each slide: sec (section), title, bullets [str | ("sub", str)], simple (plain-language box),
# table (header, rows, rel widths), img (file, width fraction), img_side (True = right of bullets)
S = []


def slide(**k):
    S.append(k)


slide(sec="Introduction", title="What is an API, and what is GraphQL?",
      bullets=["Apps (Instagram, banking, hospital portals) talk to their servers through an **API**.",
               "**GraphQL** is a modern API style made by Facebook: one address, and the app asks for *exactly* the data it wants.",
               ("sub", "Example: “give me my name, my documents, and the files inside my folder” – in one request."),
               "Flexible and fast – so it is now widely used.",
               "But the flexibility opens a new security hole."],
      simple="REST is like a fixed restaurant menu. GraphQL is like telling the waiter exactly what to bring. Very convenient – but the kitchen must still check that you only get *your* order.")

slide(sec="Introduction", title="The Threat: BOLA",
      bullets=["**BOLA = Broken Object Level Authorization.**",
               "The server knows *who* you are (you logged in), but forgets to check whether the item you asked for is *yours*.",
               "Attacker simply changes a number: `resource(id: 101)` → `resource(id: 102)` and reads someone else’s data.",
               "Ranked **#1 risk** in the OWASP API Security Top 10 (2023).",
               "Firewalls cannot see it – the request looks completely normal."],
      simple="Like a hotel key card that opens every room if you just type a different room number. You are a real guest – but you should only open your own room.")

slide(sec="Introduction", title="Our Solution in One Line",
      bullets=["**GraphQL-Shield**: a security gateway placed in front of any GraphQL app.",
               "It checks ownership at **two independent points**:",
               ("sub", "**Layer 1** – before the request runs: “does this request name anything that isn’t yours?”"),
               ("sub", "**Layer 2** – while it runs: “is every item actually being returned or changed yours?”"),
               "Novel idea: Layer 2 also **reports what Layer 1 missed**, so the system measures and repairs its own gaps."],
      simple="Two security guards: one at the hotel entrance checks your request, one in the corridor checks every door you open – and writes down anything the entrance guard missed.")

slide(sec="Problem Statement & Motivation", title="Problem Statement",
      bullets=["**Problem:** Design and implement a runtime defence that stops logged-in users of a GraphQL API from reading or changing objects they do not own – in every form GraphQL allows – while:",
               ("sub", "keeping legitimate access working,"),
               ("sub", "adding very little delay,"),
               ("sub", "and showing where the defence itself is incomplete.")],
      table=(["Form of attack", "Example", "ID visible in request?"],
             [["Direct", "resource(id: 102)", "Yes"],
              ["Nested", "user(id:101){resource(id:102)}", "Yes, deeper"],
              ["Disguised", "variable, alias, fragment, batch", "Only after decoding"],
              ["Relationship", "folder(201){children{...}}", "No – hidden"],
              ["Write", "updateResource(id:102, ...)", "Yes"]], [2, 4, 2.4]))

slide(sec="Problem Statement & Motivation", title="Motivation – Why This Matters",
      bullets=["BOLA directly causes data breaches of personal, medical and financial records.",
               "Existing tools only **test** for BOLA before release, or need a hand-written rule for **every field** – one forgotten rule silently leaks data.",
               "Checking only the request cannot see items reached through links (folder → children).",
               "Wrongly placed blocks in GraphQL can wipe out the user’s **own** data too (null propagation).",
               "No existing defence tells the developer **where it is weak**."],
      simple="Current locks either get checked once at the factory, or need a separate lock on every drawer. We want a lock that checks itself and tells you when a drawer was left open.")

slide(sec="Objectives", title="Objectives",
      bullets=["**Block every form of BOLA** – direct, nested, disguised, relationship and write attacks.",
               "**Defence in depth:** two independent layers (before and during execution).",
               "**Cross-layer evidence:** Layer 2 records every object Layer 1 never checked.",
               "**Blind-spot prediction:** XGBoost model with SHAP explanations, trained from that evidence.",
               "**Self-repairing configuration:** verified fixes, applied only with admin approval.",
               "**Formal security properties** (Safety, Non-interference, Write safety, Availability) tested automatically.",
               "**Close side channels** – same error and same timing for “not yours” and “does not exist”.",
               "**Secure accounts** (hashed passwords, lockout, token revocation) and **low overhead** (~1 ms)."])

slide(sec="Literature Survey", title="Literature Survey",
      table=(["Work", "Approach", "Limitation for us"],
             [["OWASP API Top 10 (2023) [1]", "Ranks BOLA as #1 API risk", "Guidance only"],
              ["GraphQLer (Tsai et al., 2025) [2]", "Replays GraphQL requests as other users", "Test-time, no runtime blocking"],
              ["AuthProbe (Barach, 2026) [3]", "Multi-identity BOLA testing from OpenAPI", "REST only, test-time"],
              ["Santos Filho et al. (2025) [4]", "OpenAPI → Petri nets attack models", "REST only, detection"],
              ["BolaZ (Wu et al., 2026) [5]", "Static taint + runtime checks (Spring Boot)", "Java REST, no self-measurement"],
              ["Lambers et al. (2026) [6]", "Taint analysis for graph APIs", "Static only"],
              ["graphql-shield library [7]", "Permission rule per type/field", "Many rules; can null own data"],
              ["Hartig & Pérez; Cha et al. [8],[9]", "GraphQL semantics, query cost", "Not about ownership"],
              ["Kaur (2026) [11]; CVE-2022-39275 [12]", "100+ real BOLA bug reports; Saleor ID bug", "Shows the threat is real"]],
             [3.2, 3.6, 2.8]), small=True)

slide(sec="Literature Survey", title="Key Observations from the Survey",
      bullets=["**Testing tools** find BOLA before deployment but give no protection at runtime – and most target REST, not GraphQL.",
               "**Enforcement tools** either inspect only the request (miss relationship links) or need one rule per field (leak when one is forgotten).",
               "**GraphQL research** studies query cost and semantics, not *who owns* the data.",
               "**Classic security principles** – reference monitor, complete mediation, non-interference – are well known but never combined into a self-checking GraphQL defence."],
      simple="Others built either a scanner (finds problems before opening day) or a rulebook (one rule per door). Nobody built a guard that also audits itself.")

slide(sec="Research Gap", title="Research Gap",
      bullets=["**1.** No runtime defence covers **all** GraphQL BOLA forms (relationship links are missed).",
               "**2.** No defence **measures itself** – none uses one layer to check another’s coverage.",
               "**3.** No **automatic, verified repair** of a wrong security configuration.",
               "**4.** **Availability ignored** – rule-based tools can delete the user’s own data from the answer.",
               "**5.** **Side channels** – different errors or timings reveal which objects exist.",
               "**6.** No stated and **tested security properties**.",
               "**7.** Tied to **one framework**."],
      simple="GraphQL-Shield is designed to close each of these seven gaps.")

slide(sec="Proposed System", title="Proposed System: GraphQL-Shield",
      bullets=["Configured once with a small **ShieldConfig**: which data types are private, and how to find an item’s owner.",
               "**No security code needed inside the app** itself.",
               "**Attacker model:** a real, logged-in user who tries to read or change other people’s items.",
               "**Four guarantees** (for a normal user *u*):",
               ("sub", "**P1 Safety** – the answer never contains another user’s object."),
               ("sub", "**P2 Non-interference** – changing other users’ data never changes *u*’s answer."),
               ("sub", "**P3 Write safety** – *u* can never modify or delete others’ objects."),
               ("sub", "**P4 Availability** – *u*’s own objects are always returned.")])

slide(sec="Proposed System", title="Main Components",
      bullets=["**Layer 1 – Entrance gate:** reads the request before it runs; any foreign ID → HTTP 403, nothing executes.",
               "**Layer 2 – Inside guard:** checks every object actually returned and every write target; removes foreign items.",
               "**Cross-layer evidence:** logs every object Layer 1 never saw → shows Layer 1’s blind spots.",
               "**Blind-spot predictor:** XGBoost on 17 request features (advisory only).",
               "**Self-repair:** diagnoses the gap, proposes a fix, replays old traffic to verify it, admin approves.",
               "**Uniform denials**, **account protection**, **tamper-evident (hash-chained) audit log**, **live dashboard**."])

slide(sec="System Architecture / Methodology", title="System Architecture",
      img=("fig7_1.png", 0.92),
      simple="Request → Layer 1 (block if foreign ID) → app runs → Layer 2 (remove foreign items) → only your data comes back. Disagreements between the layers feed the predictor and the self-repair module.")

slide(sec="System Architecture / Methodology", title="Methodology: Life of One Request",
      img=("fig7_2.png", 0.78))

slide(sec="System Architecture / Methodology", title="Methodology: How Each Part Works",
      bullets=["**Layer 1:** walks the parsed query, decodes every ID (variables, defaults, aliases, fragments, batches, Relay IDs), looks up the owner – one foreign ID rejects the whole request.",
               "**Layer 2:** runs inside the GraphQL engine; checks the real mutation target before the write; filters lists *before* GraphQL’s null rules apply, so your own data survives.",
               "**Evidence:** Layer 1 marks what it checked; Layer 2 records anything unmarked = proof of a Layer 1 gap.",
               "**Self-repair:** a fix is offered only if replay shows it closes gaps and blocks no legitimate request.",
               "**Evaluation:** 6 research questions – ablation, fault detection, properties, comparison, latency, self-repair."])

slide(sec="Implementation", title="Implementation: Technology Stack",
      table=(["Component", "Technology"],
             [["Language / web", "Python 3.13, FastAPI, Uvicorn"],
              ["GraphQL", "Strawberry, graphql-core, Graphene, Ariadne"],
              ["Authentication", "JWT (HS256), PBKDF2-SHA256 passwords, lockout"],
              ["Database", "SQLite with connection pooling"],
              ["Machine learning", "XGBoost, scikit-learn, SHAP"],
              ["Testing", "pytest, Hypothesis – 427 automated tests"],
              ["Comparison baseline", "Node.js + graphql-shield 7.6.5"],
              ["Front-end / DevOps", "HTML/JS dashboard, Docker, GitHub Actions"]], [3, 6]),
      simple="Two separate apps are protected (a document app and a clinic app with patient records) – the clinic app has zero security code of its own.")

slide(sec="Implementation", title="Implementation: Live Demo Scenarios",
      table=(["Demo (user 101 attacks)", "Request", "Outcome"],
             [["Legitimate access", "resource(id: 101)", "200 OK"],
              ["Direct BOLA", "resource(id: 102)", "403 – Layer 1"],
              ["Nested BOLA", "user(101){resource(102)}", "403 – Layer 1"],
              ["Unauthorised write", "updateResource(102, \"Hacked\")", "Blocked, DB unchanged"],
              ["Relationship traversal", "resource(201){children}", "200 – foreign child removed"],
              ["Admin override", "admin reads resource(102)", "200 – logged"]], [2.6, 3.8, 2.8]),
      simple="Dashboard (/dashboard): run every attack with one click, switch layers off to see what each one stops, view the ML models, self-repair and the audit log.")

slide(sec="Results and Discussion", title="Result 1: Which Layer Stops Each Attack?",
      table=(["Attack", "Both layers", "L1 only", "L2 only", "None"],
             [["Direct", "L1", "L1", "L2", "leaked"],
              ["Nested lookup", "L1", "L1", "L2", "leaked"],
              ["Inline fragment", "L1", "L1", "L2", "leaked"],
              ["Relationship", "L2", "**leaked**", "L2", "leaked"],
              ["Batch", "L1", "L1", "L2", "leaked"],
              ["Update mutation", "L1", "L1", "L2", "leaked"]], [2.6, 1.6, 1.6, 1.6, 1.6]),
      simple="Layer 1 alone misses the hidden “children” attack; Layer 2 catches it. Together: zero leaks, and most attacks stopped before anything runs.")

slide(sec="Results and Discussion", title="Result 2: The Evidence Finds Bugs",
      bullets=["**Real bug found:** Layer 1 ignored default values of variables – 585 requests slipped past it (Layer 2 still stopped them). Fixed.",
               "**17 bugs deliberately planted** in Layer 1, 5 runs each:",
               ("sub", "**17 / 17 detected**, **0 false alarms**."),
               ("sub", "A one-line rule predicts affected requests with F1 = 0.966.")],
      img=("fig9_1.png", 0.48), img_side=True,
      simple="The value is in the evidence, not the fancy model – XGBoost is no better than simple logistic regression.")

slide(sec="Results and Discussion", title="Result 3: Properties, Leaks and Comparison",
      bullets=["**P1–P4 hold** with protection on (Hypothesis, 120 examples each); P1–P3 fail with it off – proving the tests work.",
               "**4 hidden leak channels found and closed** (error messages, interfaces, counts, refused deletes).",
               "**Timing side channel closed:** 0.352 ms gap before fix → no measurable gap after.",
               "**vs. graphql-shield** (13 attacks, 5 normal requests):"],
      table=(["Measure", "GraphQL-Shield", "graphql-shield"],
             [["Attacks leaked", "0 / 13", "0 / 13"],
              ["Legitimate requests broken", "**0 / 5**", "**1 / 5**"],
              ["Configuration written", "~4 entries + owner lookup", "8 entries + 4 rules"]], [3, 3, 3]))

slide(sec="Results and Discussion", title="Result 4: Speed and Self-Repair",
      img=("fig9_2.png", 0.46), img_side=True,
      bullets=["Protection costs **about 1 ms** per request (with connection pooling).",
               "**Self-repair:** 10 planted config mistakes × 3 runs:",
               ("sub", "**30 / 30** detected and fixed by the first verified repair"),
               ("sub", "**33 / 33** wrong repairs refused"),
               ("sub", "**0** legitimate requests blocked"),
               "**Limitations:** apps and attacks written by us; synthetic ML data; owner-or-admin policies only."])

slide(sec="Conclusion", title="Conclusion",
      bullets=["Checking ownership at **two independent points** stops BOLA in every form tested – including hidden relationship attacks.",
               "Layer 2’s record of what Layer 1 missed **detected all 17 planted bugs** with no false alarms.",
               "The same evidence **repaired all 10 configuration mistakes** and refused all 33 wrong fixes.",
               "Side channels closed; own data never lost; **~1 ms overhead**; works on 4 Python GraphQL frameworks.",
               "Demonstrates defence in depth, complete mediation and fail-safe defaults on a modern API."],
      simple="We built a lock that not only keeps intruders out, but also notices when it is weak and fixes itself – with an admin’s approval.")

slide(sec="Future Scope", title="Future Scope",
      bullets=["Test on real open-source GraphQL apps (e.g. Saleor) with independent attackers.",
               "Richer policies: sharing, teams, attribute-based access control.",
               "Suggest code patches, not only configuration fixes.",
               "Measure timing over real networks; production deployment with TLS, Redis, Kong / Envoy.",
               "Train ML models on real anonymised traffic.",
               "Port to Node.js (Apollo), Java and Go; add MFA / OAuth 2.0; stream logs to SIEM tools."])

REFS = [
    "OWASP, “API Security Top 10 – 2023: API1 Broken Object Level Authorization,” 2023.",
    "O. Tsai et al., “GraphQLer: Enhancing GraphQL security with context-aware API testing,” arXiv:2504.13358, 2025.",
    "J. Barach, “AuthProbe: Specification-driven, multi-identity detection of BOLA,” arXiv:2607.20574, 2026.",
    "A. Santos Filho, R. J. Rodríguez, E. L. Feitosa, “Automated BOLA attack detection in REST APIs through OpenAPI to colored Petri nets,” Int. J. Inf. Security, 24(2), 2025.",
    "A. Wu et al., “Rethinking broken object level authorization attacks under zero trust principle,” ACM TOSEM, 2026.",
    "L. Lambers et al., “Taint analysis for graph APIs focusing on broken access control,” LMCS, 22(1), 2026.",
    "graphql-shield, npm package v7.6.5.",
    "O. Hartig, J. Pérez, “Semantics and complexity of GraphQL,” WWW, 2018.",
    "A. Cha et al., “A principled approach to GraphQL query cost analysis,” ESEC/FSE, 2020.",
    "E. Wittern et al., “An empirical study of GraphQL schemas,” ICSOC, 2019.",
    "B. Kaur, “Broken object level authorization in the wild,” arXiv:2605.25865, 2026.",
    "CVE-2022-39275: Saleor mutations did not validate object ID types, 2022.",
    "GraphQL Foundation, “GraphQL specification: Handling field errors.”",
    "J. P. Anderson, “Computer security technology planning study,” ESD-TR-73-51, 1972.",
    "J. H. Saltzer, M. D. Schroeder, “The protection of information in computer systems,” Proc. IEEE, 1975.",
    "J. A. Goguen, J. Meseguer, “Security policies and security models,” IEEE S&P, 1982.",
    "W. M. McKeeman, “Differential testing for software,” Digital Tech. J., 1998.",
    "Y. Jia, M. Harman, “An analysis and survey of mutation testing,” IEEE TSE, 2011.",
    "K. Claessen, J. Hughes, “QuickCheck,” ICFP, 2000.",
    "D. R. MacIver et al., “Hypothesis: A new approach to property-based testing,” JOSS, 2019.",
    "A. Ratner et al., “Snorkel: Rapid training data creation with weak supervision,” PVLDB, 2017.",
    "T. Chen, C. Guestrin, “XGBoost: A scalable tree boosting system,” KDD, 2016.",
    "S. M. Lundberg, S.-I. Lee, “A unified approach to interpreting model predictions,” NeurIPS, 2017.",
]

PAPER = (["Item", "Details"],
         [["Title", "GraphQL-Shield: Dual-Layer Enforcement Against GraphQL BOLA with Cross-Layer Coverage Evidence"],
          ["Template", "IEEE Conference (two-column)"],
          ["Authors", "[Author 1], [Author 2], [Author 3], [Author 4]"],
          ["Keywords", "GraphQL, API security, BOLA, access control, defense in depth, fault injection, property-based testing"],
          ["Length", "8 pages, 23 references, 2 figures, 7 tables"],
          ["Files", "paper/main.tex, paper/references.bib, paper/main.pdf"]], [1.6, 7.4])

SECTIONS = ["Introduction", "Problem Statement & Motivation", "Objectives", "Literature Survey", "Research Gap",
            "Proposed System", "System Architecture / Methodology", "Implementation", "Results and Discussion",
            "Conclusion", "Future Scope", "References", "Research Paper Template"]

# ------------------------------------------------------------------ LaTeX
def tex_esc(s):
    out = []
    for ch in s:
        out.append({"&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
                    "~": r"\textasciitilde{}", "^": r"\^{}", "\\": r"\textbackslash{}"}.get(ch, ch))
    return "".join(out)


def tex(s):
    parts = re.split(r"(\*\*.+?\*\*|\*[^*]+?\*|`[^`]+`)", s)
    o = ""
    for p in parts:
        if p.startswith("**"):
            o += r"\textbf{" + tex(p[2:-2]) + "}"
        elif p.startswith("`"):
            o += r"\texttt{" + tex_esc(p[1:-1]) + "}"
        elif p.startswith("*") and len(p) > 2:
            o += r"\emph{" + tex_esc(p[1:-1]) + "}"
        else:
            o += tex_esc(p)
    return o.replace("→", r"$\rightarrow$").replace("≥", r"$\geq$").replace("×", r"$\times$").replace("~1", r"$\sim$1")


def tex_bullets(bl):
    o, sub = [r"\begin{itemize}"], False
    for b in bl:
        if isinstance(b, tuple):
            if not sub:
                o.append(r"\begin{itemize}"); sub = True
            o.append(r"\item " + tex(b[1]))
        else:
            if sub:
                o.append(r"\end{itemize}"); sub = False
            o.append(r"\item " + tex(b))
    if sub:
        o.append(r"\end{itemize}")
    o.append(r"\end{itemize}")
    return "\n".join(o)


def tex_table(t, small=False):
    head, rows, w = t
    tot = sum(w)
    cols = "".join(r">{\raggedright\arraybackslash}p{%.3f\linewidth}" % ((0.97 - 0.036 * len(w)) * x / tot) for x in w)
    o = [r"\begin{center}", r"\footnotesize" if small else r"\small", r"\renewcommand{\arraystretch}{%s}" % ("1.05" if small else "1.12"),
         r"\begin{tabular}{" + cols + "}", r"\toprule",
         " & ".join(r"\textbf{" + tex(h) + "}" for h in head) + r" \\", r"\midrule"]
    for i, r in enumerate(rows):
        pre = r"\rowcolor{rowgrey}" if i % 2 else ""
        o.append(pre + " & ".join(tex(c) for c in r) + r" \\")
    o += [r"\bottomrule", r"\end{tabular}", r"\end{center}"]
    return "\n".join(o)


def tex_simple(s):
    return r"\begin{simplebox}" + tex(s) + r"\end{simplebox}"


def build_tex():
    L = [r"""% GraphQL-Shield -- Review 3 presentation (Beamer)
% Compile: pdflatex slides.tex  (run twice)   -- figures are in ./figures
\documentclass[aspectratio=169,11pt]{beamer}
\usetheme{Madrid}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage{booktabs,array,colortbl}
\usepackage[most]{tcolorbox}
\graphicspath{{figures/}}

\definecolor{navy}{HTML}{1F3A5F}
\definecolor{teal}{HTML}{1690A8}
\definecolor{tealbg}{HTML}{E6F4F7}
\definecolor{rowgrey}{HTML}{F2F4F7}
\setbeamercolor{structure}{fg=navy}
\setbeamercolor{palette primary}{bg=navy,fg=white}
\setbeamercolor{palette secondary}{bg=teal,fg=white}
\setbeamercolor{palette tertiary}{bg=navy,fg=white}
\setbeamercolor{frametitle}{bg=navy,fg=white}
\setbeamercolor{title}{bg=navy,fg=white}
\setbeamercolor{block title}{bg=teal,fg=white}
\setbeamertemplate{navigation symbols}{}
\setbeamertemplate{itemize item}{\color{teal}$\blacktriangleright$}
\setbeamertemplate{itemize subitem}{\color{teal}--}
\setbeamerfont{itemize/enumerate subbody}{size=\small}

% "In simple words" box for non-technical listeners
\newtcolorbox{simplebox}{enhanced,colback=tealbg,colframe=teal,boxrule=0.6pt,arc=2pt,
  left=6pt,right=6pt,top=3pt,bottom=3pt,fontupper=\small,
  title={\small\textbf{In simple words}},coltitle=white,colbacktitle=teal,
  attach boxed title to top left={xshift=6pt,yshift*=-\tcboxedtitleheight/2},top=7pt,boxed title style={boxrule=0pt,arc=2pt}}

\title[GraphQL-Shield]{GraphQL-Shield}
\subtitle{Dual-Layer Protection of GraphQL APIs against Broken Object Level Authorization (BOLA)}
\author[Team Name]{[Student Name 1] \and [Student Name 2] \and [Student Name 3] \and [Student Name 4]}
\institute[]{Guide: [Guide Name], [Designation]\\[2pt] Department of [Department], [College / University Name]}
\date{Review 3}

\begin{document}

\begin{frame}
  \titlepage
\end{frame}

\begin{frame}{Outline}
  \begin{columns}[T]
    \begin{column}{0.48\textwidth}
      \begin{enumerate}
"""]
    for i, s in enumerate(SECTIONS[:7], 1):
        L.append(r"        \item " + tex(s) + "\n")
    L.append(r"""      \end{enumerate}
    \end{column}
    \begin{column}{0.48\textwidth}
      \begin{enumerate}\setcounter{enumi}{7}
""")
    for s in SECTIONS[7:]:
        L.append(r"        \item " + tex(s) + "\n")
    L.append(r"""      \end{enumerate}
    \end{column}
  \end{columns}
\end{frame}
""")
    cur = None
    for s in S:
        if s["sec"] != cur:
            cur = s["sec"]
            L.append("\n%% " + "=" * 60 + "\n\\section{" + tex(cur) + "}\n")
        L.append(r"\begin{frame}{" + tex(s["title"]) + "}\n")
        if s.get("img") and s.get("img_side"):
            f, w = s["img"]
            L.append(r"\begin{columns}[c]" + "\n" + r"\begin{column}{%.2f\textwidth}" % (0.98 - w) + "\n")
            L.append(tex_bullets(s["bullets"]) + "\n")
            L.append(r"\end{column}" + "\n" + r"\begin{column}{%.2f\textwidth}" % w + "\n")
            L.append(r"\centering\includegraphics[width=\linewidth]{" + f + "}\n")
            L.append(r"\end{column}" + "\n" + r"\end{columns}" + "\n")
        else:
            if s.get("bullets"):
                L.append(tex_bullets(s["bullets"]) + "\n")
            if s.get("img"):
                f, w = s["img"]
                h = "0.55" if s.get("simple") else "0.80"
                L.append(r"\begin{center}\includegraphics[width=%.2f\linewidth,height=%s\textheight,keepaspectratio]{%s}\end{center}" % (w, h, f) + "\n")
        if s.get("table"):
            L.append(tex_table(s["table"], s.get("small")) + "\n")
        if s.get("simple"):
            L.append(r"\vfill" + "\n" + tex_simple(s["simple"]) + "\n")
        L.append(r"\end{frame}" + "\n")
    # references
    L.append("\n\\section{References}\n")
    for part, (a, b) in enumerate([(0, 12), (12, len(REFS))], 1):
        L.append(r"\begin{frame}{References (%d/2)}" % part + "\n" + r"\scriptsize" + "\n" +
                 r"\begin{enumerate}\setlength{\itemsep}{1pt}" + ("\\setcounter{enumi}{%d}" % a if a else "") + "\n")
        for k, r in enumerate(REFS[a:b], a + 1):
            L.append(r"\item[{[%d]}] " % k + tex(r) + "\n")
        L.append(r"\end{enumerate}" + "\n" + r"\end{frame}" + "\n")
    L.append("\n\\section{Research Paper Template}\n" + r"\begin{frame}{Research Paper (IEEE Conference Template)}" + "\n")
    L.append(tex_table(PAPER) + "\n")
    L.append(tex_simple("The full work is written up as an 8-page IEEE two-column research paper, compiled from LaTeX.") + "\n")
    L.append(r"\end{frame}" + "\n")
    L.append(r"""
\begin{frame}
  \centering
  \vfill
  {\Huge\textbf{\color{navy}Thank You}}\\[12pt]
  {\Large Questions?}\\[18pt]
  \small Code: \url{https://github.com/Chinmayanand03/GraphQL-Shield-}
  \vfill
\end{frame}

\end{document}
""")
    (OUT / "slides.tex").write_text("".join(L), encoding="utf-8")


# ------------------------------------------------------------------ PowerPoint
def build_pptx():
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu
    from pptx.dml.color import RGBColor
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
    from PIL import Image

    NAVY, TEAL, TEALBG, GREY, WHITE = (RGBColor(0x1F, 0x3A, 0x5F), RGBColor(0x16, 0x90, 0xA8),
                                       RGBColor(0xE6, 0xF4, 0xF7), RGBColor(0xF2, 0xF4, 0xF7), RGBColor(255, 255, 255))
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    W, H = prs.slide_width, prs.slide_height
    blank = prs.slide_layouts[6]
    FONT = "Calibri"
    page = [0]

    def runs(par, text, size, color=None, bold=False):
        for p in re.split(r"(\*\*.+?\*\*|\*[^*]+?\*|`[^`]+`)", text):
            if not p:
                continue
            r = par.add_run()
            if p.startswith("**"):
                r.text, r.font.bold = p[2:-2], True
            elif p.startswith("`"):
                r.text, r.font.name = p[1:-1], "Consolas"
            elif p.startswith("*") and len(p) > 2:
                r.text, r.font.italic = p[1:-1], True
            else:
                r.text = p
            r.font.size = Pt(size)
            if bold:
                r.font.bold = True
            if r.font.name != "Consolas":
                r.font.name = FONT
            if color is not None:
                r.font.color.rgb = color

    def rect(sl, x, y, w, h, fill, line=None):
        sh = sl.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
        sh.fill.solid(); sh.fill.fore_color.rgb = fill
        if line is None:
            sh.line.fill.background()
        else:
            sh.line.color.rgb = line
        sh.shadow.inherit = False
        return sh

    def new(title):
        sl = prs.slides.add_slide(blank)
        page[0] += 1
        bar = rect(sl, 0, 0, W, Inches(0.95), NAVY)
        tf = bar.text_frame; tf.margin_left = Inches(0.5); tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.LEFT
        runs(p, title, 28, WHITE, True)
        rect(sl, 0, Inches(0.95), W, Inches(0.06), TEAL)
        foot = rect(sl, 0, H - Inches(0.38), W, Inches(0.38), NAVY)
        ft = foot.text_frame; ft.margin_left = Inches(0.5); ft.margin_right = Inches(0.5)
        ft.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = ft.paragraphs[0]; runs(p, "GraphQL-Shield  |  Review 3", 11, WHITE)
        nb = sl.shapes.add_textbox(W - Inches(1.5), H - Inches(0.38), Inches(1.0), Inches(0.38))
        nb.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        q = nb.text_frame.paragraphs[0]; q.alignment = PP_ALIGN.RIGHT; runs(q, str(page[0]), 11, WHITE)
        return sl

    def bullets(sl, bl, x, y, w, h, size=20):
        tb = sl.shapes.add_textbox(x, y, w, h)
        tf = tb.text_frame; tf.word_wrap = True
        first = True
        for b in bl:
            p = tf.paragraphs[0] if first else tf.add_paragraph()
            first = False
            sub = isinstance(b, tuple)
            text = b[1] if sub else b
            p.level = 1 if sub else 0
            p.space_after = Pt(6)
            mark = p.add_run(); mark.text = ("      –  " if sub else "▸  "); mark.font.color.rgb = TEAL
            mark.font.size = Pt(size - (3 if sub else 0)); mark.font.name = FONT; mark.font.bold = True
            runs(p, text, size - (3 if sub else 0), RGBColor(0x22, 0x22, 0x22))
        return tb

    def simple(sl, text, y=None):
        h = Inches(1.0)
        y = y if y is not None else H - Inches(0.38) - h - Inches(0.15)
        box = rect(sl, Inches(0.5), y, W - Inches(1.0), h, TEALBG, TEAL)
        tf = box.text_frame; tf.word_wrap = True; tf.margin_left = Inches(0.2); tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.LEFT
        runs(p, "In simple words:  ", 16, TEAL, True)
        runs(p, text, 16, RGBColor(0x22, 0x22, 0x22))

    def table(sl, t, x, y, w, size=14):
        head, rows, wr = t
        n = len(rows) + 1
        rh = Inches(0.42)
        gt = sl.shapes.add_table(n, len(head), x, y, w, rh * n).table
        tot = sum(wr)
        for j, f in enumerate(wr):
            gt.columns[j].width = Emu(int(w * f / tot))
        for i in range(n):
            gt.rows[i].height = rh
            for j in range(len(head)):
                c = gt.cell(i, j)
                c.margin_left = c.margin_right = Inches(0.08); c.margin_top = c.margin_bottom = Inches(0.03)
                c.vertical_anchor = MSO_ANCHOR.MIDDLE
                tf = c.text_frame; tf.word_wrap = True
                p = tf.paragraphs[0]
                if i == 0:
                    runs(p, head[j], size, WHITE, True)
                    c.fill.solid(); c.fill.fore_color.rgb = NAVY
                else:
                    runs(p, rows[i - 1][j], size, RGBColor(0x22, 0x22, 0x22))
                    c.fill.solid(); c.fill.fore_color.rgb = GREY if i % 2 == 0 else WHITE
        return rh * n

    def picture(sl, f, x, y, maxw, maxh):
        path = OUT / "figures" / f
        iw, ih = Image.open(path).size
        sc = min(maxw / iw, maxh / ih)
        pw, ph = int(iw * sc), int(ih * sc)
        sl.shapes.add_picture(str(path), x + (maxw - pw) // 2, y + (maxh - ph) // 2, pw, ph)

    # title slide
    sl = prs.slides.add_slide(blank); page[0] += 1
    rect(sl, 0, 0, W, H, NAVY)
    rect(sl, 0, Inches(4.15), W, Inches(0.08), TEAL)
    tb = sl.shapes.add_textbox(Inches(0.8), Inches(1.3), W - Inches(1.6), Inches(2.8)); tf = tb.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]; runs(p, "GraphQL-Shield", 48, WHITE, True)
    p = tf.add_paragraph(); runs(p, "Dual-Layer Protection of GraphQL APIs against Broken Object Level Authorization (BOLA)", 24, RGBColor(0xCF, 0xE8, 0xEE))
    tb = sl.shapes.add_textbox(Inches(0.8), Inches(4.5), W - Inches(1.6), Inches(2.5)); tf = tb.text_frame; tf.word_wrap = True
    for i, line in enumerate(["Review 3", "[Student Name 1]  ·  [Student Name 2]  ·  [Student Name 3]  ·  [Student Name 4]",
                              "Guide: [Guide Name], [Designation]", "Department of [Department], [College / University Name]"]):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        runs(p, line, 20 if i else 22, WHITE, i == 0); p.space_after = Pt(6)

    # outline
    sl = new("Outline")
    for col, items in enumerate([SECTIONS[:7], SECTIONS[7:]]):
        tb = sl.shapes.add_textbox(Inches(0.8 + col * 6.2), Inches(1.4), Inches(5.8), Inches(5.4)); tf = tb.text_frame
        for i, s in enumerate(items):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            runs(p, f"{i + 1 + col * 7:>2}.  ", 22, TEAL, True); runs(p, s, 22, RGBColor(0x22, 0x22, 0x22))
            p.space_after = Pt(10)

    top = Inches(1.25)
    for s in S:
        sl = new(s["title"])
        bottom = H - Inches(0.38) - (Inches(1.25) if s.get("simple") else Inches(0.15))
        y = top
        if s.get("img") and s.get("img_side"):
            f, wfrac = s["img"]
            bw = int((W - Inches(1.0)) * (1 - wfrac)) - Inches(0.2)
            bullets(sl, s["bullets"], Inches(0.5), y, bw, bottom - y, 18)
            picture(sl, f, Inches(0.5) + bw + Inches(0.2), y, W - Inches(1.0) - bw - Inches(0.2), bottom - y)
        else:
            if s.get("bullets"):
                nb = len(s["bullets"])
                size = 18 if (s.get("table") or nb > 6) else 20
                if s.get("table"):
                    h = Inches(0.42 * nb + 0.5 * sum(len(b if isinstance(b, str) else b[1]) > 95 for b in s["bullets"]))
                else:
                    h = bottom - y
                bullets(sl, s["bullets"], Inches(0.5), y, W - Inches(1.0), h, size)
                y += h + Inches(0.1)
            if s.get("img"):
                picture(sl, s["img"][0], Inches(0.5), y, W - Inches(1.0), bottom - y)
        if s.get("table"):
            table(sl, s["table"], Inches(0.6), y, W - Inches(1.2), 13 if s.get("small") else 15)
        if s.get("simple"):
            simple(sl, s["simple"])

    for part, (a, b) in enumerate([(0, 12), (12, len(REFS))], 1):
        sl = new(f"References ({part}/2)")
        tb = sl.shapes.add_textbox(Inches(0.5), top, W - Inches(1.0), H - top - Inches(0.5)); tf = tb.text_frame; tf.word_wrap = True
        for i, r in enumerate(REFS[a:b]):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            runs(p, f"[{a + i + 1}]  ", 13, TEAL, True); runs(p, r, 13, RGBColor(0x22, 0x22, 0x22)); p.space_after = Pt(4)

    sl = new("Research Paper (IEEE Conference Template)")
    table(sl, PAPER, Inches(0.6), top + Inches(0.1), W - Inches(1.2), 16)
    simple(sl, "The full work is written up as an 8-page IEEE two-column research paper, compiled from LaTeX.")

    sl = prs.slides.add_slide(blank); page[0] += 1
    rect(sl, 0, 0, W, H, NAVY)
    tb = sl.shapes.add_textbox(0, Inches(2.4), W, Inches(3)); tf = tb.text_frame
    for i, (t, sz) in enumerate([("Thank You", 54), ("Questions?", 30), ("github.com/Chinmayanand03/GraphQL-Shield-", 18)]):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); p.alignment = PP_ALIGN.CENTER
        runs(p, t, sz, WHITE, i == 0); p.space_after = Pt(14)

    prs.save(OUT / "GraphQL-Shield-Review3.pptx")


build_tex()
build_pptx()
print("slides:", len(S) + 6)
