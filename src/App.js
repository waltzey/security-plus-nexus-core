import { useState, useEffect, useCallback, useMemo } from "react";

/* ═══════════════════════════════════════════════════════════════
   SECURITY+ NEXUS CORE — SY0-701 Complete Exam Preparation
   Architecture: Decoupled Content Engine (JSON) → UI Components
   Features: Active Recall, Spaced Repetition, PBQ Sim,
             Confidence Assessment, Shadow Exam, 80/20 Priority
   ═══════════════════════════════════════════════════════════════ */

// ═══ CONTENT ENGINE — 100% SY0-701 Objectives ═══

const DB = { domains: [
  {
  id:1, title:"General Security Concepts", weight:12, icon:"🛡️", color:"#00b4d8",
  objectives:[
  {id:"1.1",title:"Compare and contrast various types of security controls",
   topics:[
    {id:"1.1.1",title:"Security Controls",
     plain:"Security controls are like a castle's defenses with different jobs. Technical controls are the walls and moats (built with technology). Managerial controls are the king's laws (policies and paperwork). Operational controls are the guards walking the walls (people doing things). Physical controls are the actual drawbridge and gate (things you can touch). Each control also has a TYPE — Preventive stops attacks, Detective catches them, Corrective fixes the damage, Deterrent scares attackers away, Compensating is a Plan B, and Directive tells people what to do.",
     examTip:"When classifying controls, focus on WHO implements it (category) and WHAT IT DOES (type). A camera is physical+detective. A guard is operational+preventive.",
     tech:"NIST SP 800-53 defines control families. CATEGORIES: Technical (firewalls, IDS/IPS, ACLs, encryption, antivirus, DLP), Managerial/Administrative (risk assessments, security policies, vulnerability management programs, security frameworks), Operational (security awareness training, guard patrols, incident response procedures, media handling), Physical (bollards, mantrap/vestibule, badge readers, CCTV, fencing, lighting, locks). TYPES: Preventive (firewall rules blocking traffic, door locks, encryption, access controls), Detective (IDS, security cameras, log monitoring, audit trails), Corrective (antivirus quarantine, patching, backup restoration, incident response), Deterrent (warning banners, visible cameras, security signage), Compensating (additional monitoring when patching is delayed, MFA when passwords are weak, separation of duties), Directive (AUP, compliance policies, posted security procedures). Defense-in-depth layers multiple control categories and types.",
     terms:["Technical","Managerial","Operational","Physical","Preventive","Detective","Corrective","Deterrent","Compensating","Directive","Defense-in-depth","NIST SP 800-53"],
     tasks:["Create a 6×4 matrix mapping all control types to all categories with examples","Identify every security control in your home/office and classify it","Read NIST SP 800-53 control family overview"]},
   ],
   questions:[
    {q:"A security guard checking badges at the entrance is BEST classified as:",o:["Technical/Preventive","Operational/Preventive","Physical/Detective","Managerial/Directive"],a:1,x:"A guard is a person (operational) who blocks unauthorized entry (preventive).",d:1},
    {q:"After discovering an unpatchable zero-day, the team adds additional monitoring and network segmentation. These are:",o:["Corrective controls","Compensating controls","Detective controls","Directive controls"],a:1,x:"Compensating controls are alternative measures when primary controls cannot be implemented.",d:2},
    {q:"A login banner stating 'Unauthorized access is prohibited and will be prosecuted' is:",o:["Preventive","Detective","Deterrent","Corrective"],a:2,x:"Warning banners discourage (deter) unauthorized use without technically preventing it.",d:1},
    {q:"An organization's SIEM generating alerts from log correlation is which control type?",o:["Preventive","Corrective","Detective","Compensating"],a:2,x:"SIEM detects threats by analyzing and correlating log data.",d:1},
    {q:"Mandatory annual security awareness training for all employees is classified as:",o:["Technical/Preventive","Operational/Detective","Managerial/Directive","Physical/Deterrent"],a:2,x:"Policies requiring training = managerial controls that direct behavior.",d:2},
   ]},
  {id:"1.2",title:"Summarize fundamental security concepts",
   topics:[
    {id:"1.2.1",title:"The CIA Triad",
     plain:"Three pillars hold up ALL of security. Confidentiality: only authorized people see the data — like a sealed envelope only the recipient opens. Integrity: the data hasn't been tampered with — like a tamper-evident seal on medicine. Availability: the systems work when you need them — like a hospital ER that never closes.",
     examTip:"CIA triad: data changed=integrity. Data leaked=confidentiality. System down=availability. CompTIA describes scenarios and asks which pillar was violated.",
     tech:"Confidentiality: Encryption (AES-256 at rest, TLS 1.3 in transit), access controls (RBAC, ABAC), data classification, MFA, DLP. Integrity: Hashing (SHA-256, SHA-3), digital signatures, checksums, HMAC, version control, input validation, database constraints. Availability: Redundancy (RAID, clustering), load balancing, fault tolerance, failover, disaster recovery, UPS/generators, SLAs, auto-scaling. Trade-offs exist: higher confidentiality (encryption overhead) can reduce availability (performance). Attacks by pillar: Eavesdropping/data breach→confidentiality, data tampering/injection→integrity, DDoS/ransomware→availability.",
     terms:["Confidentiality","Integrity","Availability","Encryption","Hashing","Redundancy","DLP","SLA"],
     tasks:["Map 10 common attacks to which CIA pillar they primarily target","Explain how ransomware threatens all three pillars","Design a system prioritizing availability over confidentiality and explain trade-offs"]},
    {id:"1.2.2",title:"Non-repudiation",
     plain:"Non-repudiation means you CAN'T deny you did something. Like a notarized signature — the notary witnessed it, the signature is uniquely yours, and there's a formal record. In digital terms, digital signatures provide non-repudiation because only YOUR private key could have created that signature.",
     examTip:"Non-repudiation requires digital signatures (asymmetric crypto). Symmetric keys are shared so either party could have sent. Prove who sent it = digital signature.",
     tech:"Achieved through digital signatures: sender hashes message with SHA-256, encrypts hash with private key, recipient decrypts with sender's public key, compares hashes. If match → integrity confirmed + origin verified. Proof of integrity (data unchanged via hash comparison), Proof of origin (only private key holder could sign). Legal/compliance: audit trails, signed transactions, code signing, S/MIME email. Key distinction: Authentication = proving identity NOW. Non-repudiation = proving action in the PAST. Requires asymmetric cryptography — symmetric keys are shared so either party could have created the MAC.",
     terms:["Non-repudiation","Digital signature","Proof of origin","Proof of integrity","Asymmetric cryptography","Audit trail"],
     tasks:["Sign a file with GPG and have someone verify the signature","Explain why symmetric encryption cannot provide non-repudiation","Compare digital signatures vs HMAC for integrity and non-repudiation"]},
    {id:"1.2.3",title:"Authentication, Authorization, and Accounting (AAA)",
     plain:"Authentication = showing your ID at the door (proving who you are). Authorization = the bouncer checking if your name is on the VIP list (what you're allowed to do). Accounting = the club logging what time you arrived, what you ordered, and when you left (tracking what happened). Two big protocols handle this: RADIUS and TACACS+.",
     examTip:"RADIUS=UDP, encrypts only password, combines auth+authz. TACACS+=TCP, encrypts full packet, separates all three. TACACS+ is Cisco-originated and more granular.",
     tech:"Authentication factors: Knowledge (passwords, PINs, security questions), Possession (smart card, hardware token, phone), Inherence (fingerprint, face, retina, voice), Location (GPS, IP geolocation), Behavior (typing pattern, gait). Authorization models: RBAC, ABAC, DAC, MAC, Rule-based. Accounting: Session logging, bandwidth tracking, command history, access timestamps. RADIUS: UDP 1812/1813, encrypts only password, combines auth+authz, common for network access (VPN, WiFi). TACACS+: TCP 49, encrypts entire payload, separates auth/authz/acct, Cisco-preferred, granular command-level authorization. AAA servers: Cisco ISE, FreeRADIUS, Microsoft NPS.",
     terms:["Authentication","Authorization","Accounting","RADIUS","TACACS+","MFA factors","Identity provider"],
     tasks:["Compare RADIUS vs TACACS+ in a detailed table with protocol details","Set up FreeRADIUS in a virtual environment","Map the full AAA flow for a corporate VPN connection"]},
    {id:"1.2.4",title:"Gap Analysis",
     plain:"Gap analysis is GPS for your security program: it shows where you ARE, where you WANT to be, and plots the route between. The 'gap' is the distance between your current security posture and your target (like a framework or regulation). It can take weeks and involves lots of people, data, and honest assessment.",
     examTip:"Gap analysis questions describe comparing current state to a framework. Answer usually involves creating a remediation roadmap prioritized by risk.",
     tech:"Process: 1) Define target state — align to framework (NIST CSF, ISO 27001, CIS Controls, PCI-DSS) or organizational goals. 2) Assess current state — vulnerability scans, policy review, interviews, documentation audit, technical testing. 3) Identify gaps — missing controls, outdated procedures, insufficient training, technical shortcomings. 4) Prioritize remediation — risk-based ranking, cost-benefit analysis, quick wins vs long-term. 5) Create roadmap — timeline, budget, milestones, responsible parties, KPIs. Deliverable: Gap analysis report documenting current state, target, gaps, risk ratings, and prioritized remediation plan. Gap analysis may be required for compliance certification (ISO 27001 Stage 1 audit).",
     terms:["Gap analysis","Security posture","Baseline","Remediation roadmap","NIST CSF","ISO 27001","Current state","Target state"],
     tasks:["Perform a gap analysis of your home network against CIS Controls v8 Top 5","Create a prioritized remediation template","Research how organizations prepare for ISO 27001 certification gap analysis"]},
    {id:"1.2.5",title:"Zero Trust",
     plain:"Traditional security = castle with strong walls but free movement inside. Zero Trust = high-security building where EVERY room requires a new badge scan, background check, and reason for entry — even if you work there. The motto: 'Never trust, always verify.' No one and nothing is trusted by default.",
     examTip:"Zero Trust keywords: never trust always verify, assume breach, micro-segmentation, PDP/PEP. Verifying every request regardless of network location = Zero Trust.",
     tech:"Core tenets: 1) Verify explicitly — authenticate every request using all available data (identity, device health, location, behavior). 2) Least privilege — JIT/JEA (Just-In-Time/Just-Enough-Access), time-limited permissions. 3) Assume breach — minimize blast radius, segment access, encrypt E2E, monitor everything. NIST SP 800-207 architecture: Policy Decision Point (PDP) = policy engine + policy administrator, evaluates access requests. Policy Enforcement Point (PEP) = gateway enforcing PDP decisions at resource boundary. Control plane (PDP decisions, policy management) vs Data plane (actual data/resource access). Implementation requires: Strong identity verification (MFA, SSO), device compliance (EDR, MDM health checks), micro-segmentation (identity-based network segments), continuous monitoring (behavioral analytics, anomaly detection), least privilege enforcement.",
     terms:["Zero Trust","Never trust always verify","PDP","PEP","Control plane","Data plane","NIST SP 800-207","Micro-segmentation","JIT/JEA","Assume breach"],
     tasks:["Diagram a zero trust architecture for a 50-person company with remote workers","Compare zero trust vs perimeter-based security with specific pros/cons","Research Microsoft's Zero Trust Deployment Guide and summarize key pillars"]},
    {id:"1.2.6",title:"Physical Security",
     plain:"Physical security is the bouncer, the lock, the alarm, and the fence — protecting the REAL WORLD. The best firewall means nothing if someone can walk up and steal the server. Layers: keep them out (fences/bollards), control who enters (badges/mantraps), watch everything (cameras), and protect the environment (fire suppression/HVAC).",
     examTip:"Mantrap/vestibule prevents tailgating. Bollards stop vehicles. Faraday cage blocks signals. Fire: wet pipe (common), dry pipe (freezing), pre-action (data centers), FM-200 (electronics).",
     tech:"Perimeter: Fencing (height determines delay time), bollards (vehicle barriers), gates, security lighting, signage. Entry controls: Mantrap/security vestibule (airlock — one door must close before other opens), turnstiles, badge readers (proximity, smart card), biometric scanners (fingerprint, retina, facial), visitor logs. Surveillance: CCTV (PTZ cameras, NVR recording), motion sensors (infrared, microwave), security guards, K-9 units. Environmental: HVAC (humidity 40-60%, temperature control), fire detection (ionization for fast flames, photoelectric for smoldering), fire suppression (wet pipe — fastest, dry pipe — cold environments, pre-action — data centers, clean agent FM-200/Novec 1230 — electronics safe, no water damage), EMI shielding, Faraday cage (blocks all RF signals). Infrastructure: Cable locks, server rack locks, safe/vault, locking cabinets. Integration: Badge → triggers both physical door AND network access.",
     terms:["Bollards","Mantrap/vestibule","Badge reader","CCTV","Motion sensor","Fire suppression","FM-200","Faraday cage","Air gap"],
     tasks:["Tour your workplace/school and identify+classify every physical control","Design a comprehensive physical security plan for a small data center","Compare all fire suppression types in a table with use cases"]},
    {id:"1.2.7",title:"Deception and Disruption Technology",
     plain:"Honeypots are like leaving a fake diamond necklace in an obvious spot while the real jewels are hidden. When the thief grabs the fake, an alarm sounds and you learn exactly HOW they broke in, WHAT tools they used, and WHAT they wanted. The fake jewels teach you about real threats.",
     examTip:"Honeypots gather TTPs. Honeynets = networks of honeypots. Honeytokens = fake credentials that alert when used. DNS sinkholes redirect malicious domains.",
     tech:"Deception technologies: Honeypots (decoy systems — low interaction: simulate services/emulate OS; medium: simulate more complex services; high interaction: full OS, most realistic, most risky). Honeynets (network of honeypots simulating full enterprise infrastructure — switches, routers, servers). Honeyfiles (fake sensitive documents like 'passwords.xlsx' or 'employee_salaries.csv' that trigger alerts when opened/accessed). Honeytokens (fake data planted in databases, code repos, or systems — fake credentials, API keys, database records, AWS keys). DNS sinkhole (redirect known-malicious domain queries to a controlled server — prevents malware communication, identifies infected internal hosts). Purpose: Early warning (detect attackers before they reach production), Attacker TTP analysis (learn techniques/tools/procedures), Diversion (waste attacker time on decoys), Intelligence gathering. Tools: Cowrie (SSH/Telnet honeypot), T-Pot (multi-honeypot platform), HoneyD (simulates network topology), Thinkst Canary (commercial canary tokens).",
     terms:["Honeypot","Honeynet","Honeyfile","Honeytoken","DNS sinkhole","Low/medium/high interaction","TTP","Canary token"],
     tasks:["Deploy Cowrie SSH honeypot on a VM and analyze captured attacker sessions","Create honeytoken strategy: plant fake AWS keys and monitor for use","Set up Pi-hole as DNS sinkhole and analyze blocked queries"]},
   ],
   questions:[
    {q:"A DDoS attack that overwhelms a web server, making it inaccessible, PRIMARILY threatens:",o:["Confidentiality","Integrity","Availability","Non-repudiation"],a:2,x:"DDoS targets availability by making resources inaccessible to legitimate users.",d:1},
    {q:"In a zero trust architecture, the component that EVALUATES whether an access request should be allowed is the:",o:["Policy Enforcement Point","Policy Decision Point","Data plane","SIEM"],a:1,x:"The PDP evaluates access requests using identity, device health, location, and behavior data.",d:2},
    {q:"TACACS+ is preferred over RADIUS in enterprise environments primarily because it:",o:["Uses UDP for faster performance","Encrypts the entire packet payload","Is an open standard supported by all vendors","Supports only authentication, simplifying design"],a:1,x:"TACACS+ encrypts the entire payload (TCP 49) while RADIUS only encrypts the password field.",d:2},
    {q:"A security team deploys a system mimicking a vulnerable SSH server to capture attacker TTPs. This is a:",o:["Honeyfile","DNS sinkhole","Honeypot","Honeytoken"],a:2,x:"A honeypot is a decoy system designed to attract and study attacker behavior.",d:1},
    {q:"Which fire suppression system is MOST appropriate for a data center with running servers?",o:["Wet pipe sprinkler","Dry pipe sprinkler","Clean agent (FM-200/Novec 1230)","Deluge system"],a:2,x:"Clean agent systems suppress fire without water damage to electronics.",d:2},
    {q:"An employee digitally signs a purchase order. Later they deny sending it. The digital signature provides:",o:["Confidentiality","Availability","Authorization","Non-repudiation"],a:3,x:"Digital signatures provide non-repudiation — the sender cannot deny having signed the message.",d:1},
    {q:"Gap analysis compares an organization's current security posture against a:",o:["Penetration test result","Desired target state or framework baseline","Competitor's security program","Previous audit finding"],a:1,x:"Gap analysis measures the distance between current state and a target baseline (framework/regulation).",d:1},
   ]},
  {id:"1.3",title:"Explain the importance of change management processes",
   topics:[
    {id:"1.3.1",title:"Change Management Processes",
     plain:"Change management is air traffic control for IT. You wouldn't let every pilot land whenever they want — the tower coordinates timing, sequence, and safety. RFC = requesting permission to change. CAB = the review board that approves. Rollback plan = what to do if the change breaks things. Without this process, one bad change brings down the whole network.",
     examTip:"Every change needs RFC, CAB approval, rollback plan, and testing. Emergency changes skip CAB but need documentation after. Unauthorized change = bypass = security incident.",
     tech:"Process flow: 1) Request for Change (RFC) — documents who, what, why, when, risk assessment, rollback plan. 2) Impact analysis — dependencies, affected systems/users, testing requirements. 3) Approval — Change Advisory Board (CAB) reviews normal changes; Emergency CAB (ECAB) for urgent changes. 4) Testing — validated in sandbox/staging/dev environment. 5) Implementation — executed during scheduled maintenance window, with rollback plan ready. 6) Documentation — update CMDB, network diagrams, runbooks, SOPs. 7) Post-implementation review — verify change met objectives, no unintended effects. Change types: Standard (pre-approved, routine, low-risk — e.g., password reset), Normal (requires full CAB review — e.g., firewall rule change), Emergency (critical fix, ECAB approval, documentation completed post-implementation — e.g., zero-day patch). Stakeholders: Change owner, CAB members, implementer, affected users, management.",
     terms:["RFC","CAB","ECAB","Rollback plan","Maintenance window","Standard change","Normal change","Emergency change","Post-implementation review"],
     tasks:["Create an RFC template with all required fields","Design a change management workflow diagram","Write a rollback plan for a production firewall rule change"]},
    {id:"1.3.2",title:"Technical Change Management",
     plain:"Technical change management is the mechanic's checklist before and after working on a jet engine. Every bolt documented, every system tested, every configuration tracked. Version control means every change is recorded and reversible. A CMDB tracks every device and how they're connected.",
     examTip:"IaC means configs are version-controlled in Git. Consistent, repeatable server configuration = IaC tools (Ansible/Puppet/Chef/Terraform).",
     tech:"Version control: Git repositories track all configuration/code changes (branching, merging, pull requests, commit history, rollback capability). Configuration management tools: Ansible (agentless, YAML playbooks), Puppet (agent-based, declarative), Chef (agent-based, Ruby), SaltStack — enforce consistent state across infrastructure (Infrastructure as Code). CMDB: Configuration Management Database tracks all Configuration Items (CIs) and their relationships — servers, switches, software, licenses, dependencies. Testing pipeline: Development → Staging → Production (never skip stages). CI/CD: Continuous Integration/Continuous Deployment — automated testing and deployment reduces human error. Dependency management: Map upstream/downstream impacts before changes. Documentation requirements: Network diagrams updated, asset inventory current, runbooks/SOPs reflect changes, knowledge base articles created. Baseline: A known-good configuration state to compare against and restore to.",
     terms:["Version control","Git","CMDB","CI/CD","Configuration management","Ansible","Staging","Dependency mapping","Baseline configuration","Infrastructure as Code"],
     tasks:["Track a configuration file change through Git (init, add, commit, diff, revert)","Research Ansible basics and write a simple playbook","Create a pre-change and post-change validation checklist"]},
   ],
   questions:[
    {q:"A critical zero-day requires an emergency patch on production servers. Per change management best practices:",o:["Skip all approvals and patch immediately","Get ECAB approval, implement, then complete documentation","Wait for the next scheduled maintenance window","Apply the patch and document it later if time permits"],a:1,x:"Emergency changes use expedited ECAB approval and still require post-implementation documentation and review.",d:2},
    {q:"A change was implemented and caused unexpected service outages. The FIRST action should be:",o:["Update the CMDB","Submit a new RFC","Execute the rollback plan","Conduct a post-implementation review"],a:2,x:"The pre-prepared rollback/backout plan should be the immediate response to a failed change.",d:2},
    {q:"Which tool ensures server configurations remain consistent across hundreds of systems and can rebuild them identically?",o:["SIEM","Configuration management (Ansible/Puppet)","Vulnerability scanner","Packet analyzer"],a:1,x:"Configuration management tools automate and enforce consistent system states across infrastructure.",d:1},
    {q:"A database that tracks all IT assets, their configurations, and relationships between them is a:",o:["DNS server","CMDB","SIEM","PKI"],a:1,x:"A CMDB (Configuration Management Database) tracks all Configuration Items and their interdependencies.",d:1},
   ]},
  {id:"1.4",title:"Explain the importance of using appropriate cryptographic solutions",
   topics:[
    {id:"1.4.1",title:"Public Key Infrastructure (PKI)",
     plain:"PKI is like the DMV for the internet. Just like the DMV verifies your identity and issues a driver's license that others trust, a Certificate Authority (CA) verifies a server's identity and issues a digital certificate. When you see the padlock in your browser, a CA has vouched for that website.",
     examTip:"PKI chain: Root CA to Intermediate CA to End entity. CRL is stale list. OCSP checks real-time. OCSP stapling = server caches own status (best performance).",
     tech:"PKI components: Certificate Authority (CA) — issues and signs digital certificates (root CA and subordinate/intermediate CAs create a chain of trust). Registration Authority (RA) — verifies identity before CA issues cert. Certificate Revocation List (CRL) — periodic list of revoked certificates (serial numbers). OCSP (Online Certificate Status Protocol) — real-time revocation checking. OCSP stapling — web server periodically queries CA and 'staples' signed response to TLS handshake (reduces CA load, improves performance). Certificate chain/trust: Root CA → Intermediate CA → Server certificate. Browser trusts root CAs in its certificate store. Key escrow — trusted third party holds copy of encryption keys (controversial — government access vs privacy). Certificate pinning — client stores expected certificate hash, rejects different certs even if CA-signed (prevents MitM with rogue certificates).",
     terms:["PKI","Certificate Authority","Registration Authority","CRL","OCSP","OCSP stapling","Certificate chain","Root CA","Intermediate CA","Key escrow","Certificate pinning"],
     tasks:["Inspect a website's full certificate chain in your browser's developer tools","Generate a self-signed CA and issue a server certificate with OpenSSL","Research how OCSP stapling works and why it improves TLS performance"]},
    {id:"1.4.2",title:"Encrypting Data",
     plain:"Symmetric encryption = one key for both locking and unlocking (like a diary with one key — fast but if you share the key, anyone can read it). Asymmetric = two keys: public key locks, private key unlocks (like a mailbox — anyone drops in mail, only you can open it). In practice we use BOTH: asymmetric to securely exchange a symmetric key, then symmetric for the actual data (hybrid encryption). This is exactly how HTTPS/TLS works.",
     examTip:"Symmetric = same key (AES, fast, bulk data). Asymmetric = key pair (RSA/ECC, slow, signatures). Hybrid = asymmetric exchanges symmetric key, then symmetric for data.",
     tech:"Symmetric algorithms (single shared key): AES (Advanced Encryption Standard) — AES-128, AES-192, AES-256, block cipher, current gold standard, NIST approved. 3DES (Triple DES) — legacy, being deprecated, three rounds of DES. ChaCha20 — stream cipher, Google's alternative to AES for mobile (used in TLS). Blowfish/Twofish — older alternatives. Asymmetric algorithms (key pairs): RSA — 2048/4096-bit keys, widely used for key exchange and digital signatures. DSA (Digital Signature Algorithm). ECC (Elliptic Curve Cryptography) — smaller keys with equivalent security to larger RSA keys (256-bit ECC ≈ 3072-bit RSA), preferred for mobile/IoT. Hybrid encryption: Asymmetric encrypts a randomly generated symmetric session key → symmetric key encrypts the actual data. TLS handshake uses this exact approach. Key exchange: Diffie-Hellman (DH) — allows two parties to derive a shared secret over an insecure channel. Neither party transmits the actual key. ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) — adds perfect forward secrecy (new key per session, compromising one session doesn't compromise others).",
     terms:["AES-256","3DES","ChaCha20","RSA","ECC","Diffie-Hellman","ECDHE","Symmetric","Asymmetric","Hybrid encryption","Perfect forward secrecy","Session key"],
     tasks:["Generate RSA and ECC key pairs with OpenSSL and compare key sizes","Capture a TLS 1.3 handshake in Wireshark and identify the key exchange method","Encrypt and decrypt a file using AES-256-CBC with OpenSSL"]},
    {id:"1.4.3",title:"Key Exchange",
     plain:"The key exchange problem: how do two people agree on a secret key if someone is listening to everything they say? Diffie-Hellman solved this with clever math. Imagine you and a friend each mix a PUBLIC color with your own SECRET color. You swap mixed colors, then each adds your secret again. You both end up with the SAME final color — but an eavesdropper only saw the mixed colors and can't reverse-engineer the secrets.",
     examTip:"DHE/ECDHE = ephemeral = new key per session = perfect forward secrecy. Compromised key does not expose past sessions.",
     tech:"Diffie-Hellman (DH): Mathematical key agreement protocol. Both parties agree on public parameters (large prime p, generator g). Each generates private value, computes public value (g^private mod p), exchanges public values, each computes shared secret (other_public^own_private mod p). Result: identical shared secret without ever transmitting it. Vulnerable to MitM without authentication. DHE (Ephemeral): New DH parameters per session → perfect forward secrecy. ECDHE: Elliptic curve variant, smaller parameters, same security, faster. Used in TLS 1.3 (ECDHE is MANDATORY). Session keys: Temporary symmetric keys derived from key exchange, used only for that session. If key is compromised, only that session is affected. Key agreement vs key transport: Agreement (DH — both contribute), Transport (RSA — one party generates key, encrypts with other's public key).",
     terms:["Diffie-Hellman","DHE","ECDHE","Key agreement","Key transport","Session key","Perfect forward secrecy","MitM vulnerability"],
     tasks:["Walk through DH key exchange step-by-step with small numbers","Explain why ephemeral keys provide perfect forward secrecy","Compare TLS 1.2 key exchange options vs TLS 1.3 mandatory ECDHE"]},
    {id:"1.4.4",title:"Encryption Technologies",
     plain:"Data needs protection in three states: At rest (sitting on a disk — like valuables in a safe), In transit (moving across a network — like an armored truck), In use (being processed in memory — like performing surgery in a sealed room). Each state needs different encryption tools.",
     examTip:"Three data states: at rest (BitLocker), in transit (TLS/IPSec), in use (TEE/SGX). TPM = motherboard chip for keys. HSM = dedicated hardware appliance.",
     tech:"Data at rest: Full Disk Encryption (FDE) — BitLocker (Windows, uses TPM), FileVault (macOS), LUKS (Linux). Partition/volume encryption. File-level encryption (EFS). Database encryption (TDE — Transparent Data Encryption). Self-encrypting drives (SED — hardware encryption, OPAL standard). Data in transit: TLS 1.3 (HTTPS, mandatory ECDHE, 0-RTT resumption), IPSec (tunnel mode for VPN, transport mode for host-to-host), SSH (secure remote access, replaces Telnet), SFTP/SCP (secure file transfer). Data in use: Trusted execution environments (TEE), Intel SGX (Software Guard Extensions), ARM TrustZone, secure enclaves. Homomorphic encryption (compute on encrypted data without decrypting — still mostly experimental). Hardware security: TPM (Trusted Platform Module — hardware crypto processor on motherboard, stores keys, measures boot integrity, supports BitLocker). HSM (Hardware Security Module — dedicated appliance for key generation/storage/management, FIPS 140-2/3 validated, used by CAs and banks). Secure enclave (isolated processing area within CPU). Key stretching: bcrypt, PBKDF2, scrypt, Argon2 — add computational cost to password hashing, making brute force impractical.",
     terms:["BitLocker","FileVault","TLS 1.3","IPSec","TPM","HSM","FDE","TDE","Secure enclave","Key stretching","bcrypt","PBKDF2","OPAL"],
     tasks:["Enable BitLocker on a Windows VM and test TPM integration","Compare TLS 1.2 vs 1.3 handshake differences in detail","Research TPM vs HSM: when would you use each?"]},
    {id:"1.4.5",title:"Obfuscation",
     plain:"Obfuscation is hiding information in plain sight. Steganography hides a secret message inside a picture — the picture looks completely normal but contains hidden data. Tokenization swaps your credit card number for a random placeholder that's useless to a thief. Data masking shows 'XXXX-XXXX-XXXX-4321' instead of the full number.",
     examTip:"Steganography hides data in files. Tokenization replaces data preserving format. Data masking shows partial data. Know the differences.",
     tech:"Steganography: Hiding data within other data — images (LSB modification in pixels), audio (frequency manipulation), video, documents. Steganalysis = detecting hidden data. Common tools: OpenStego, Steghide. Not encryption — security through obscurity, often combined with encryption. Tokenization: Replace sensitive data with non-sensitive substitute (token). Token has no mathematical relationship to original (unlike encryption). Original mapped in secure token vault. Common for PCI-DSS compliance — tokenize credit card numbers so merchant systems never store real card data. Data masking: Obfuscate data for non-production use (development, testing, training). Static masking (permanent), Dynamic masking (real-time, role-based). Techniques: substitution, shuffling, number variance, nulling out. Data minimization: Collect only necessary data. Reduces risk surface. GDPR principle of data minimization.",
     terms:["Steganography","Tokenization","Data masking","Data minimization","Token vault","Steganalysis","LSB"],
     tasks:["Hide a message in an image using Steghide and extract it","Compare tokenization vs encryption for PCI-DSS compliance","Research GDPR data minimization principle and its practical implications"]},
    {id:"1.4.6",title:"Hashing and Digital Signatures",
     plain:"A hash is a fingerprint for data — completely unique, always the same length, and changes completely if even one tiny bit changes (avalanche effect). You CAN'T reverse a hash back to the original. Digital signatures combine hashing + asymmetric encryption: you hash the message, encrypt the hash with your private key. Anyone can verify with your public key.",
     examTip:"MD5 and SHA-1 DEPRECATED. SHA-256/SHA-3 current. HMAC adds secret key. Salt = random value before hashing to defeat rainbow tables.",
     tech:"Hash properties: Deterministic (same input → same output), Fixed length output, One-way (irreversible), Collision-resistant (extremely unlikely two inputs produce same hash), Avalanche effect (tiny change → completely different hash). Algorithms: MD5 (128-bit — BROKEN, collision attacks demonstrated, DO NOT USE for security), SHA-1 (160-bit — deprecated, collision found by Google in 2017), SHA-2 family: SHA-256 (256-bit, current standard), SHA-512 (512-bit). SHA-3 (Keccak — different internal structure from SHA-2, backup standard). Uses: Password storage (with salt — random data prepended to password before hashing, prevents rainbow table attacks), File integrity verification, Digital signatures, Code signing, Blockchain/cryptocurrency. HMAC (Hash-based Message Authentication Code): Hash + secret key → verifies both integrity AND authenticity (but not non-repudiation since key is shared). Digital signature process: 1) Sender hashes message (SHA-256), 2) Sender encrypts hash with own PRIVATE key, 3) Recipient decrypts hash with sender's PUBLIC key, 4) Recipient independently hashes received message, 5) Compare hashes — match = integrity confirmed + origin verified + non-repudiation achieved.",
     terms:["SHA-256","SHA-3","MD5","HMAC","Digital signature","Salt","Rainbow table","Avalanche effect","Collision resistance","Code signing"],
     tasks:["Hash a file with MD5, SHA-1, and SHA-256 — compare outputs and understand why MD5 is insecure","Create a salted hash for a password manually and explain why salt prevents rainbow tables","Verify a Linux ISO download using published SHA-256 hash"]},
    {id:"1.4.7",title:"Blockchain Technology",
     plain:"A blockchain is like a shared notebook where every page is linked to the previous one with a special seal. If someone tries to change page 50, the seal breaks and everyone notices. No single person controls the notebook — it's distributed across thousands of copies. Great for proving something happened and wasn't altered.",
     examTip:"Blockchain = distributed immutable ledger. CompTIA focuses on use cases: supply chain, identity, audit trails. Not just cryptocurrency.",
     tech:"Blockchain: Distributed, decentralized, immutable ledger using cryptographic hashing. Each block contains: transactions, timestamp, hash of previous block (chain link), nonce (proof of work). Changing any block invalidates all subsequent blocks. Consensus mechanisms: Proof of Work (mining — computationally expensive, Bitcoin), Proof of Stake (validators stake cryptocurrency, Ethereum 2.0). Applications in security: Cryptocurrency (Bitcoin, Ethereum), Supply chain verification, Identity management, Immutable audit logs, Smart contracts (self-executing code on blockchain), Certificate transparency. Limitations: Scalability (transaction speed), Energy consumption (PoW), 51% attack (theoretical majority control), Immutability is both a feature and a problem (can't delete errors/illegal content).",
     terms:["Blockchain","Distributed ledger","Immutable","Consensus","Proof of Work","Smart contract","Decentralized"],
     tasks:["Research how blockchain is being used for supply chain security","Explain the 51% attack and why it's mostly theoretical","Compare blockchain-based identity management vs traditional PKI"]},
    {id:"1.4.8",title:"Certificates",
     plain:"A digital certificate is an internet ID card. It says 'I am example.com, and DigiSign CA vouches for me.' It contains the website's public key, who issued it, when it expires, and the CA's digital signature. Your browser checks this 'ID card' every time you visit a secure website — that's what the padlock means.",
     examTip:"DV=weakest validation. OV=org validated. EV=extended (strongest). Wildcard=one subdomain level. SAN=multiple domains in one cert.",
     tech:"X.509 certificate format: Subject (who it's issued to), Issuer (CA that signed it), Serial number, Validity period (not before/not after), Subject's public key, Digital signature of CA, Extensions (key usage, subject alternative names). Certificate types: Domain Validation (DV) — verifies domain ownership only, issued quickly, basic. Organization Validation (OV) — verifies organization identity, more trust. Extended Validation (EV) — rigorous verification, previously showed green bar. Wildcard (*.domain.com) — covers all subdomains. Subject Alternative Name (SAN/UCC) — multiple domains on one cert. Self-signed — not trusted by default, used for testing/internal. Code signing — verifies software publisher and integrity. Root certificate — CA's own cert, pre-installed in trust stores. CSR process: 1) Generate key pair, 2) Create Certificate Signing Request (CSR) with subject info + public key, 3) Submit CSR to CA, 4) CA verifies identity, 5) CA signs and issues certificate. Certificate formats: PEM (.pem, .crt — Base64), DER (.der — binary), PFX/PKCS#12 (.pfx, .p12 — includes private key), PKCS#7 (.p7b — certificate chain only).",
     terms:["X.509","DV","OV","EV","Wildcard","SAN","CSR","Root certificate","Self-signed","Code signing","PEM","DER","PFX","PKCS#12"],
     tasks:["Inspect 5 different websites' certificates and identify DV vs OV vs EV","Generate a CSR and self-sign a certificate with OpenSSL","Research certificate transparency logs and their role in detecting rogue CAs"]},
   ],
   questions:[
    {q:"Two parties need to establish a shared secret key over an insecure network without transmitting the key itself. They should use:",o:["AES-256","RSA encryption","Diffie-Hellman key exchange","SHA-256 hashing"],a:2,x:"Diffie-Hellman enables deriving a shared secret over an insecure channel without transmitting the key.",d:2},
    {q:"OCSP stapling improves TLS performance because:",o:["The CA checks revocation faster","The client queries the CA directly","The web server caches and presents the signed OCSP response","It eliminates the need for certificates"],a:2,x:"The server periodically queries the CA and staples the signed response to the TLS handshake, eliminating client-to-CA round trips.",d:3},
    {q:"An organization destroys encryption keys to render stored encrypted data permanently unreadable. This is:",o:["Degaussing","Crypto-shredding","Secure erase","Tokenization"],a:1,x:"Crypto-shredding destroys the key, making encrypted data permanently inaccessible without physical media destruction.",d:2},
    {q:"Which password hashing algorithm is recommended specifically because it adds computational cost to resist brute force?",o:["MD5","SHA-1","bcrypt","AES-256"],a:2,x:"bcrypt (and PBKDF2/Argon2) are key stretching algorithms that intentionally slow hashing to resist brute force.",d:2},
    {q:"A wildcard certificate for *.example.com would cover:",o:["Only example.com","All subdomains of example.com","All domains ending in example.com","Sub-subdomains like a.b.example.com"],a:1,x:"Wildcard covers one level of subdomains (mail.example.com, www.example.com) but NOT sub-subdomains.",d:2},
    {q:"Hiding a secret message within an image file is an example of:",o:["Encryption","Hashing","Steganography","Tokenization"],a:2,x:"Steganography hides data within other data (images, audio, video) without visible alteration.",d:1},
    {q:"Which certificate type requires the MOST rigorous identity verification by the CA?",o:["Domain Validation (DV)","Organization Validation (OV)","Extended Validation (EV)","Self-signed"],a:2,x:"EV certificates require the most thorough verification of the organization's legal identity.",d:1},
   ]},
]},
  {
  id:2, title:"Threats, Vulnerabilities, and Mitigations", weight:22, icon:"⚔️", color:"#ff4757",
  objectives:[
  {id:"2.1",title:"Compare and contrast common threat actors and motivations",
   topics:[
    {id:"2.1.1",title:"Threat Actors",
     plain:"Threat actors are different types of bad guys with different skills and goals. Nation-states = government spy agencies with unlimited money (espionage). Organized crime = mafia running ransomware for cash. Hacktivists = political protesters with keyboards. Insiders = your own employees gone rogue (most dangerous because they already have access). Unskilled attackers/script kiddies = teenagers using tools they downloaded. Shadow IT = employees using unauthorized apps and creating blind spots.",
     examTip:"Nation-state=unlimited resources, APT. Organized crime=financial. Hacktivist=political. Insider=most dangerous (legitimate access). Unskilled=script kiddies.",
     tech:"Types and attributes: Nation-state/APT (highest sophistication, unlimited resources, objectives: espionage, sabotage, IP theft, persistent campaigns lasting months/years — APT28/Fancy Bear Russia, APT29/Cozy Bear Russia, Lazarus Group DPRK, APT41 China). Organized crime (financial motivation, RaaS — Ransomware-as-a-Service, credential markets, money laundering, moderate-high sophistication). Hacktivists (political/social motivation, DDoS, website defacement, data leaks — Anonymous, LulzSec). Insider threats (current/former employees/contractors, intentional malicious OR unintentional negligent, most dangerous due to legitimate access and knowledge of systems, hardest to detect). Unskilled attackers (low sophistication, use existing tools/scripts/exploits, opportunistic). Shadow IT (employees using unauthorized tools/cloud services, creates unmonitored/unprotected data pathways). Motivations: Data exfiltration, Financial gain, Espionage, Disruption/chaos, Philosophical/political beliefs, Revenge, War. MITRE ATT&CK framework maps Tactics, Techniques, and Procedures (TTPs) to threat actor groups.",
     terms:["APT","Nation-state","Organized crime","Hacktivist","Insider threat","Unskilled attacker","Shadow IT","TTPs","MITRE ATT&CK","RaaS","Motivation"],
     tasks:["Research MITRE ATT&CK and identify TTPs for one APT group","Create a threat actor comparison matrix with all attributes","Design 5 insider threat detection indicators for a SOC"]},
    {id:"2.1.2",title:"Threat Vectors and Attack Surfaces",
     plain:"A threat vector is HOW the attacker gets in — the door they use. The attack surface is ALL the possible doors combined. More services running = more doors = bigger attack surface. Common vectors: email (phishing), web (malicious sites), USB drives (baiting), wireless (evil twin), supply chain (compromised vendor), social media (OSINT), physical (tailgating).",
     examTip:"Attack surface = all entry points. Attack vector = specific path used. Email is number 1 vector. CompTIA asks which vector was used in a scenario.",
     tech:"Vectors: Message-based (email phishing, SMS/smishing, instant messaging, social media messages), Image-based (malicious images exploiting parser vulnerabilities), File-based (malicious attachments — Office macros, PDFs, executables), Voice call (vishing — social engineering over phone), Removable device (infected USB — autorun, BadUSB/Rubber Ducky), Vulnerable software (unpatched applications, zero-days, misconfigured services), Unsecure networks (open WiFi, unencrypted protocols), Wireless (rogue AP, evil twin, Bluetooth attacks), Supply chain (compromised vendor software/hardware/updates — SolarWinds), Direct access (physical — stolen devices, console access, dumpster diving), Cloud services (misconfigured storage, insecure APIs). Attack surface management: Reduce by disabling unnecessary services/ports, patch management, network segmentation, application allow-listing, minimize internet-facing services, regular vulnerability scanning, principle of least functionality.",
     terms:["Threat vector","Attack surface","Phishing","Vishing","Smishing","Supply chain","Zero-day","Removable device","OSINT","Attack surface management"],
     tasks:["Map your organization's attack surface — list all internet-facing services","Research the SolarWinds supply chain attack vector in detail","Perform OSINT on yourself and identify what information attackers could use"]},
   ],
   questions:[
    {q:"An attack group maintains persistent access to a defense contractor for 18 months, exfiltrating classified documents. This is MOST consistent with:",o:["Unskilled attacker","Hacktivist","Nation-state APT","Insider threat"],a:2,x:"Long-term, sophisticated espionage with high resources = nation-state APT.",d:2},
    {q:"An employee installs an unauthorized cloud storage application, creating an unmonitored data pathway. This represents:",o:["Intentional insider threat","Shadow IT","Social engineering success","Supply chain attack"],a:1,x:"Shadow IT = unauthorized technology use creating security blind spots.",d:1},
    {q:"Which threat actor type is MOST motivated by financial gain through ransomware and credential theft?",o:["Nation-state","Hacktivist","Organized crime","Insider"],a:2,x:"Organized crime is primarily financially motivated, operating ransomware-as-a-service and credential markets.",d:1},
   ]},
  {id:"2.2",title:"Explain common threat vectors and attack surfaces",
   topics:[
    {id:"2.2.1",title:"Phishing",
     plain:"Phishing = fishing for your information using fake bait. Regular phishing casts a wide net (mass emails). Spear phishing targets YOU specifically using details they researched (your name, job, boss's name). Whaling targets the big fish — CEOs and executives. Vishing does it over the phone. Smishing does it via text message.",
     examTip:"Phishing=generic. Spear phishing=targeted. Whaling=executives. Vishing=voice. Smishing=SMS. BEC=impersonating exec for wire fraud.",
     tech:"Types: Phishing (mass campaign, generic lures — 'Your account has been compromised'), Spear phishing (targeted individual using OSINT — references real colleagues, projects, events), Whaling (targeting C-suite executives specifically — fake board communications, legal notices), Business Email Compromise/BEC (impersonating executive or vendor for wire transfers or data — often no malware, pure social engineering, FBI reports billions in losses). Indicators: Urgency/fear tactics, generic greetings, misspelled sender domains (rn looks like m), suspicious links (hover to check), unexpected attachments, requests for sensitive info, grammatical errors. Prevention: Security awareness training with simulated phishing campaigns (track click rates, repeat offender remediation), Email filtering (gateway scanning), SPF/DKIM/DMARC (email authentication), MFA (limits damage from compromised credentials), URL inspection/sandbox detonation, reporting mechanisms (phishing button in email client).",
     terms:["Phishing","Spear phishing","Whaling","BEC","Email filtering","Security awareness training","Phishing simulation"],
     tasks:["Analyze 5 phishing emails — identify which social engineering principles each exploits","Research a real BEC case and calculate the financial impact","Set up a GoPhish phishing simulation campaign"]},
    {id:"2.2.2",title:"Impersonation",
     plain:"Impersonation is pretending to be someone you're not to get what you want. Pretexting = creating a fake scenario ('Hi, I'm from IT support, I need your password to fix an issue'). Brand impersonation = fake emails that look exactly like they're from Microsoft or your bank. Watering hole = poisoning the well that everyone drinks from.",
     examTip:"Pretexting=fabricated scenario. Typosquatting=misspelled domains. Watering hole=compromise trusted site. Know Cialdini: authority, urgency, scarcity, social proof.",
     tech:"Pretexting: Fabricated scenario to establish trust and extract information or gain access. Attacker may impersonate IT support, vendor, executive, law enforcement. Often involves research (OSINT) to make the story believable. Brand impersonation: Spoofed emails/websites mimicking trusted brands (Microsoft, Amazon, banks). Uses similar logos, formatting, domains. Typosquatting: Registering misspelled domains (gooogle.com, microsof.com) to catch typos. Watering hole: Compromise websites frequented by target group — instead of attacking targets directly, poison their favorite resource. Requires reconnaissance to identify target habits. Social engineering principles (Cialdini): Authority (impersonating boss/IT/law enforcement), Urgency/scarcity ('Act now or account locked'), Social proof ('Everyone in your department has already updated'), Familiarity/liking (building rapport), Intimidation ('Legal action will be taken'), Consensus ('Standard procedure, everyone does this').",
     terms:["Pretexting","Brand impersonation","Typosquatting","Watering hole","Social engineering principles","Authority","Urgency","Scarcity","Social proof"],
     tasks:["Identify typosquatting domains for 3 major brands using DNS tools","Create a social engineering scenario using 3 Cialdini principles","Research a real watering hole attack case study"]},
    {id:"2.2.3",title:"Social Engineering Techniques",
     plain:"Social engineering is hacking people, not computers. Tailgating = following someone through a secure door before it closes. Baiting = leaving infected USB drives in the parking lot hoping someone plugs them in. Shoulder surfing = looking over someone's shoulder to see their password. Dumpster diving = searching trash for sensitive documents.",
     examTip:"Tailgating=following through door. Baiting=infected USB. Shoulder surfing=watching typing. Dumpster diving=searching trash.",
     tech:"Tailgating/piggybacking: Following authorized person through secure door. Tailgating = without their knowledge. Piggybacking = with their consent ('Can you hold the door?'). Prevention: mantraps, turnstiles, security awareness, challenge unknown persons. Baiting: Leaving malware-infected USB drives, CDs in public areas. Exploits human curiosity. USB Rubber Ducky/BadUSB = USB device that acts as keyboard and executes pre-programmed attacks. Prevention: disable autorun, USB port blocking, security awareness. Shoulder surfing: Observing screens, keyboards, PIN pads. Prevention: privacy screens, awareness of surroundings, PIN cover techniques. Dumpster diving: Searching discarded documents, storage media, equipment for sensitive information. Prevention: shredding (cross-cut, not strip-cut), degaussing media, secure disposal procedures. Eliciting information: Casual conversation designed to extract sensitive details without appearing suspicious. Invoice scams: Fake invoices for services never ordered, hoping accounts payable processes them automatically. Influence campaigns: Large-scale information manipulation, often nation-state sponsored, targeting public opinion through social media and fake news.",
     terms:["Tailgating","Piggybacking","Baiting","Shoulder surfing","Dumpster diving","Eliciting information","Invoice scams","Influence campaigns","USB Rubber Ducky"],
     tasks:["Conduct a physical security assessment — test for tailgating vulnerabilities","Create a security awareness poster covering top 5 social engineering techniques","Research USB Rubber Ducky capabilities and how to defend against them"]},
   ],
   questions:[
    {q:"An attacker sends a targeted email to the CFO referencing a real upcoming board meeting, requesting an urgent wire transfer to a new account. This is:",o:["General phishing","Smishing","Whaling/BEC","Vishing"],a:2,x:"Whaling targets executives with personalized context; combined with BEC for financial fraud.",d:2},
    {q:"A user receives a text claiming their bank account is locked with a link to 'verify' credentials:",o:["Vishing","Smishing","Pharming","Pretexting"],a:1,x:"Smishing = SMS-based phishing.",d:1},
    {q:"Attacker compromises a cybersecurity news site knowing target employees visit daily:",o:["Spear phishing","Watering hole attack","Drive-by download","Typosquatting"],a:1,x:"Watering hole = compromising websites the target group frequents.",d:2},
    {q:"Leaving infected USB drives in a company parking lot is an example of:",o:["Tailgating","Baiting","Pretexting","Shoulder surfing"],a:1,x:"Baiting exploits curiosity by leaving malware-laden devices where targets will find them.",d:1},
    {q:"An attacker calls the help desk pretending to be a new employee who forgot their password. This uses which principle?",o:["Scarcity","Authority","Pretexting with familiarity","Technical exploit"],a:2,x:"Pretexting creates a fabricated scenario (new employee) to manipulate the help desk into resetting credentials.",d:2},
   ,{q:"Motion-sensor lighting to discourage break-ins:",o:["Physical/Deterrent","Technical/Preventive","Operational/Detective","Physical/Preventive"],a:0,x:"Lighting physically deters attackers.",d:1},{q:"Background checks for new hires is:",o:["Operational/Preventive","Technical/Detective","Managerial/Preventive","Physical/Preventive"],a:2,x:"Background check policies are management-level preventive controls.",d:2},{q:"Digital signature provides:",o:["Confidentiality+availability","Integrity+non-repudiation","Confidentiality+integrity","Availability+non-repudiation"],a:1,x:"Signatures prove integrity and non-repudiation. No encryption.",d:2},{q:"Password+fingerprint+phone OTP = how many factors?",o:["One","Two","Three","Four"],a:2,x:"Knowledge+inherence+possession = 3 different categories.",d:1},{q:"TACACS+ vs RADIUS: which encrypts full packet?",o:["RADIUS","TACACS+","Both equally","Neither"],a:1,x:"TACACS+ encrypts full packet. RADIUS only encrypts password.",d:2},{q:"Zero Trust replaces network perimeter with:",o:["VPN","Identity verification per request","DMZ","Firewall"],a:1,x:"Never trust, always verify. Identity replaces perimeter.",d:2},{q:"Ansible/Puppet/Chef are for:",o:["Packet capture","Configuration management/IaC","Vulnerability scanning","Password cracking"],a:1,x:"IaC tools for consistent configuration management.",d:2},{q:"TLS 1.3 mandatory key exchange for forward secrecy:",o:["RSA","DHE/ECDHE","AES-256","SHA-384"],a:1,x:"TLS 1.3 requires ephemeral DH. RSA key exchange removed.",d:2},{q:"Key stretching (bcrypt/PBKDF2) protects passwords by:",o:["AES encryption","Making hashing intentionally slow","Plaintext storage","Symmetric encryption"],a:1,x:"Adds computational cost making brute-force prohibitively slow.",d:2},{q:"Wildcard cert *.example.com covers:",o:["sub.sub.example.com","example.com","mail.example.com","All levels"],a:2,x:"Wildcards cover one subdomain level only.",d:2},{q:"Tokenization best use:",o:["Email encryption","Credit card numbers in database","Password hashing","VPN tunnels"],a:1,x:"Replaces sensitive data with tokens of same format — ideal for PCI-DSS.",d:2},{q:"Developer pushes code directly to production — which failure?",o:["No rollback","Bypassed CAB approval","No version control","Insufficient testing"],a:1,x:"CAB must approve changes before production deployment.",d:1},{q:"OCSP stapling: server does what?",o:["Eliminates certs","Fetches and caches own cert status","Encrypts OCSP","Uses blockchain"],a:1,x:"Server fetches its cert status and staples it to TLS handshake.",d:3},{q:"Bitcoin uses which consensus mechanism?",o:["Proof of Stake","Proof of Authority","Proof of Work","Delegated PoS"],a:2,x:"PoW requires solving complex math puzzles, consuming massive energy.",d:1},{q:"Honeypot MOST valuable output:",o:["Attacker name","TTPs used","Files stolen","Time spent"],a:1,x:"Honeypots capture TTPs to understand attacker methods.",d:2}]},
  {id:"2.3",title:"Explain various types of vulnerabilities",
   topics:[
    {id:"2.3.1",title:"Application Vulnerabilities",
     plain:"SQL injection = writing 'and give me all the money' on a bank deposit slip and the teller processes it blindly. Buffer overflow = pouring water past the edge of a glass onto the table, then controlling where it flows. Race condition = two people trying to withdraw from the same ATM at the exact same time, and the system gets confused.",
     examTip:"SQL injection: OR 1=1, UNION SELECT. Fix=parameterized queries. Never concatenate user input into SQL strings.",
     tech:"Injection attacks: SQL injection (insert malicious SQL into input fields — ' OR 1=1--, UNION SELECT, blind SQLi uses true/false responses, time-based SQLi uses delays; prevention: parameterized queries/prepared statements, stored procedures, input validation, WAF). Command injection (execute OS commands through application — ; ls -la, | cat /etc/passwd). LDAP injection (manipulate LDAP queries). XML injection/XXE (XML External Entity — read local files, SSRF). Buffer overflow: Write beyond allocated memory buffer → overwrite adjacent memory → execute arbitrary code. Stack-based (most common) vs heap-based. Prevention: ASLR (Address Space Layout Randomization — randomize memory locations), DEP/NX (Data Execution Prevention/No eXecute — prevent code execution from data segments), bounds checking, safe programming languages (Rust, Go), stack canaries. Race conditions: TOCTOU (Time of Check to Time of Use) — exploit timing gap between security check and resource use. Example: check file permissions, attacker swaps file before read. Prevention: mutex locks, atomic operations, proper synchronization.",
     terms:["SQL injection","Command injection","XXE","Buffer overflow","ASLR","DEP","Race condition","TOCTOU","Parameterized query","Stack canary"],
     tasks:["Complete SQL injection challenges on DVWA or PortSwigger Academy","Write a parameterized query and compare to a vulnerable concatenated query","Research the ASLR bypass techniques and why DEP complements it"]},
    {id:"2.3.2",title:"Web-based Vulnerabilities",
     plain:"XSS (Cross-Site Scripting) = putting a hidden note in a library book that forces the next reader to hand over their wallet. CSRF = tricking someone into signing a document they didn't read while they're logged into their bank. Directory traversal = sneaking out of the public lobby to access restricted areas by following the hallway signs backwards.",
     examTip:"XSS: reflected (URL), stored (DB), DOM. Fix=CSP+HttpOnly+sanitization. CSRF=forged requests. Fix=anti-CSRF tokens.",
     tech:"XSS (Cross-Site Scripting): Inject malicious JavaScript into web pages viewed by other users. Reflected/Non-persistent (payload in URL, executed when victim clicks link — search results), Stored/Persistent (payload saved in database, executes for every visitor — comments, profiles, MOST DANGEROUS), DOM-based (client-side JavaScript manipulation). Prevention: Output encoding (HTML entities), Content Security Policy (CSP) headers, input sanitization, HttpOnly cookies (prevents JavaScript cookie access). CSRF (Cross-Site Request Forgery): Trick authenticated user into performing unintended actions. Attacker crafts page that submits request to target site using victim's session. Prevention: Anti-CSRF tokens (unique per request), SameSite cookie attribute, checking Referer header. Server-Side Request Forgery (SSRF): Trick server into making requests to internal resources. Can access internal APIs, cloud metadata endpoints (169.254.169.254). Directory traversal: ../../etc/passwd — escape web root to read system files. Prevention: input validation, chroot jail, canonicalization.",
     terms:["XSS","Reflected XSS","Stored XSS","DOM XSS","CSRF","SSRF","Directory traversal","CSP","HttpOnly","Anti-CSRF token"],
     tasks:["Practice XSS on DVWA — achieve reflected and stored XSS","Explain the difference between XSS and CSRF with diagrams","Research SSRF attacks against cloud metadata endpoints (AWS 169.254.169.254)"]},
    {id:"2.3.3",title:"Operating System Vulnerabilities",
     plain:"An unpatched OS is like driving with recalled brakes you never got fixed. Patch Tuesday = Microsoft releases security fixes on the 2nd Tuesday of every month. End of Life (EOL) means the manufacturer stopped making patches entirely — your OS is now a sitting duck with no more fixes coming, ever.",
     examTip:"EOL=no development. EOSL=no patches=urgent risk. CompTIA says OS is no longer supported - risk = unpatched vulnerabilities.",
     tech:"Common OS vulns: Unpatched systems (Patch Tuesday — 2nd Tuesday/month, Microsoft releases batch of security updates; other vendors have similar cycles). Default configurations (unnecessary services running, default ports open, sample files present, verbose error messages). Unnecessary services (each running service = additional attack surface). End of Life/End of Service Life (EOL/EOSL — no more security patches, must upgrade or implement compensating controls). Privilege escalation vulnerabilities (local exploits allowing user→admin). Kernel vulnerabilities (most severe — full system compromise). Driver vulnerabilities (third-party drivers running in kernel mode). Known DLLs (DLL search order hijacking). Patch management: Scan for missing patches → Test in staging → Deploy to production → Verify → Document. Automated patch management tools: WSUS, SCCM/MECM (Microsoft), Qualys, ManageEngine.",
     terms:["Patch Tuesday","EOL","EOSL","Privilege escalation","Kernel vulnerability","Patch management","WSUS","Default configuration"],
     tasks:["Check your system for missing patches using appropriate tools","Research 3 recent high-severity CVEs affecting your OS","Create a patch management policy with response SLAs by severity level"]},
    {id:"2.3.4",title:"Hardware Vulnerabilities",
     plain:"Hardware vulnerabilities are flaws in the physical chips themselves — imagine discovering the locks in every house in the world have a hidden bypass. Spectre and Meltdown were exactly this: fundamental flaws in how CPUs optimize performance that allowed attackers to read protected memory.",
     examTip:"Spectre/Meltdown=CPU speculative execution. Firmware attacks survive OS reinstall. Side-channel=timing/power analysis.",
     tech:"CPU vulnerabilities: Spectre (speculative execution side-channel — tricks CPU into executing unauthorized code speculatively, reads data from other processes), Meltdown (allows reading kernel memory from user space). Both are fundamental CPU architecture flaws affecting Intel, AMD, ARM. Mitigations: microcode updates, OS patches, but performance impact. Firmware vulnerabilities: BIOS/UEFI exploits (bootkits — persist below OS level, survive OS reinstalls), firmware supply chain attacks. JTAG/debug interfaces: Hardware debugging ports left accessible → direct memory access, bypass all software security. End of life hardware: No firmware updates available, known vulnerabilities permanently unpatched. Rowhammer: Repeated memory access causes bit flips in adjacent RAM rows → privilege escalation. Hardware implants: Rogue chips added during manufacturing (supply chain). Side-channel attacks: Power analysis, electromagnetic emanation, timing analysis — extract cryptographic keys by monitoring physical characteristics.",
     terms:["Spectre","Meltdown","Firmware","Bootkit","JTAG","Side-channel attack","Rowhammer","Hardware implant"],
     tasks:["Check if your CPU is vulnerable to Spectre/Meltdown and what mitigations are applied","Research firmware update processes for network equipment","Explain side-channel attacks and why they're difficult to prevent"]},
    {id:"2.3.5",title:"Virtualization Vulnerabilities",
     plain:"Virtual machines share the same physical hardware. VM escape = breaking out of your virtual apartment into the building's infrastructure — now you can access everyone else's apartment. VM sprawl = so many VMs nobody knows they exist, like forgotten rooms in a mansion that nobody locks.",
     examTip:"VM escape=break out to host. Type 1=bare-metal (secure). Type 2=on host OS. VM sprawl=uncontrolled growth nobody manages.",
     tech:"VM escape: Exploiting hypervisor vulnerability to break out of guest VM and access host OS or other VMs. Most critical virtualization vulnerability — compromises entire host. Type 1 (bare-metal: VMware ESXi, Hyper-V) vs Type 2 (hosted: VirtualBox, VMware Workstation) — Type 1 smaller attack surface. Resource reuse: Data remnants in shared memory, CPU cache, or disk when VM is deprovisioned. Sensitive data from one tenant accessible to another. Prevention: memory scrubbing, secure deprovisioning. VM sprawl: Uncontrolled proliferation of VMs — unpatched, unmonitored, forgotten VMs become attack targets. Prevention: VM lifecycle management, automated discovery, tagging requirements. Hyperjacking: Installing rogue hypervisor beneath legitimate OS — all VM operations compromised. Inter-VM attacks: VMs on same host communicating through virtual switches — potentially bypass network security controls. Data commingling: Multiple tenants' data on same physical storage — logical separation must be enforced.",
     terms:["VM escape","Hypervisor","Type 1/Type 2","VM sprawl","Resource reuse","Hyperjacking","Data commingling"],
     tasks:["Research a real VM escape CVE and how it was exploited","Compare Type 1 vs Type 2 hypervisor security implications","Create a VM lifecycle management checklist"]},
    {id:"2.3.6",title:"Cloud-specific Vulnerabilities",
     plain:"Cloud misconfiguration is like leaving your storage unit unlocked AND putting a sign on it saying 'OPEN — HELP YOURSELF.' Public S3 buckets have leaked millions of records because someone checked the wrong box. You're responsible for securing what you put IN the cloud, even though the provider secures the cloud itself.",
     examTip:"Cloud misconfig is number 1 cloud vulnerability. Public S3 buckets, overpermissive IAM. You always own your data and access controls.",
     tech:"Misconfigured storage: Public S3 buckets, Azure blobs, GCP storage — massive data exposures. Insecure APIs: Weak authentication, missing rate limiting, excessive data exposure, broken access controls. Insufficient logging: Cloud environments may not have adequate logging enabled by default — must configure CloudTrail (AWS), Activity Log (Azure), Cloud Audit Logs (GCP). Shared tenancy risks: Multiple customers on same physical infrastructure — noisy neighbor (performance), side-channel attacks, data isolation concerns. Identity and access management: Overly permissive IAM policies, unused service accounts, missing MFA for cloud console. Shadow IT cloud: Employees using personal cloud accounts for work data. Cloud account hijacking: Compromised credentials → full access to cloud resources. Serverless/function risks: Event injection, excessive permissions, vulnerable dependencies.",
     terms:["Misconfigured storage","Insecure API","Shared tenancy","Cloud account hijacking","Insufficient logging","Shadow IT cloud","IAM over-provisioning"],
     tasks:["Audit an AWS account for public S3 buckets using AWS CLI","Research 3 real cloud data breaches caused by misconfiguration","Review AWS Well-Architected security pillar checklist"]},
    {id:"2.3.7",title:"Supply Chain Vulnerabilities",
     plain:"Supply chain attacks poison the river upstream so everyone downstream gets sick. SolarWinds: attackers injected malicious code into the Orion software UPDATE. Every organization that installed the update — including US government agencies — got backdoored through a TRUSTED source.",
     examTip:"SolarWinds=supply chain via compromised update. SBOM=list all components. Log4Shell=vulnerable library affecting millions.",
     tech:"Software supply chain: Compromised updates/patches (SolarWinds Orion — malicious code in legitimate update affected 18,000+ organizations including US Treasury, DHS). Compromised development tools (IDE plugins, build systems). Malicious open-source packages (typosquatting package names in npm, PyPI). Hardware supply chain: Counterfeit components, hardware implants during manufacturing, firmware tampering. Service provider attacks: MSP (Managed Service Provider) compromise → access to all MSP clients. SBOM (Software Bill of Materials): Complete inventory of all software components, libraries, dependencies. Enables rapid vulnerability identification when a library is found vulnerable (Log4Shell — Log4j affected millions of applications). Mitigation: Vendor assessment/due diligence, SBOM tracking, code signing verification, vendor monitoring, trusted suppliers, secure development lifecycle, hash verification of all downloads.",
     terms:["Supply chain attack","SolarWinds","SBOM","Code signing","Vendor assessment","MSP compromise","Log4Shell","Trusted supplier"],
     tasks:["Research the SolarWinds attack timeline from initial compromise to detection","Generate an SBOM for a software project using available tools","Explain how Log4Shell demonstrated supply chain risk at scale"]},
    {id:"2.3.8",title:"Misconfiguration Vulnerabilities",
     plain:"Misconfiguration is leaving your front door unlocked, your windows open, and a 'WELCOME' mat with your alarm code printed on it. It's the #1 cloud vulnerability. Default passwords, open ports, verbose error messages, excessive permissions — all mistakes that hand attackers the keys.",
     examTip:"Default credentials searchable on Shodan. CIS Benchmarks define secure configs. Vendor defaults = misconfiguration vulnerability.",
     tech:"Common misconfigurations: Default credentials (admin/admin, admin/password — Shodan finds thousands), Open permissions (world-readable files, public database access, 0.0.0.0/0 security groups), Unnecessary services/ports (reduce attack surface by disabling what's not needed), Verbose error messages (stack traces revealing internal architecture, library versions, file paths), Directory listing enabled (web server shows all files), Missing security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security), Insecure protocols (Telnet, FTP, HTTP, SNMPv1/v2c instead of secure alternatives), Improper certificate management (expired certs, self-signed in production, weak algorithms). Impact: Often the easiest vulnerability to exploit and easiest to prevent. Prevention: Secure baselines, automated compliance scanning, configuration management tools, regular audits, CIS benchmarks.",
     terms:["Default credentials","Open permissions","Verbose errors","Directory listing","Security headers","Secure baseline","CIS benchmarks"],
     tasks:["Scan a test server with Nmap and identify unnecessary open ports/services","Check 5 websites for missing security headers using securityheaders.com","Research Shodan and what misconfigured devices it commonly finds"]},
    {id:"2.3.9",title:"Mobile Device Vulnerabilities",
     plain:"Jailbreaking/rooting your phone is like removing all the locks and security cameras from your house because they were 'inconvenient.' You get more freedom but zero protection. Sideloading apps = installing software from untrusted sources, like buying medicine from a stranger instead of a pharmacy.",
     examTip:"Jailbreak (iOS) / root (Android) removes controls. SIM swap steals numbers. MDM enforces policies. Sideloading=outside official store.",
     tech:"Jailbreaking (iOS) / Rooting (Android): Removes manufacturer security restrictions, allows unsigned code execution, voids warranty, disables security features (sandboxing, verified boot). Sideloading: Installing apps from outside official stores — bypasses app store security review, malware risk. Third-party app stores: Less rigorous security screening than Google Play/Apple App Store. Outdated OS: Mobile OS updates often stop for older devices — known vulnerabilities permanently unpatched. Insecure WiFi connections: Auto-connecting to open/evil twin networks. Lost/stolen devices: Physical access to data without encryption/strong PIN. Camera/microphone access: Malicious apps with excessive permissions for surveillance. SMS-based attacks: SIM swapping (social engineering carrier to transfer phone number → bypass SMS MFA), SS7 vulnerabilities. MDM bypass: Users circumventing Mobile Device Management controls.",
     terms:["Jailbreaking","Rooting","Sideloading","SIM swapping","MDM bypass","Outdated OS","Third-party app store"],
     tasks:["Research SIM swapping attacks and how to protect against them","Review Android/iOS app permissions model differences","Evaluate your own phone's security: OS version, encryption, lock method"]},
    {id:"2.3.10",title:"Zero-day Vulnerabilities",
     plain:"A zero-day is a vulnerability that even the software maker doesn't know about yet — they've had ZERO days to fix it. It's like discovering your house has a hidden back door that the builder forgot to tell you about, and burglars already know about it. There's no patch, no fix, no defense yet.",
     examTip:"Zero-day=no patch exists. Virtual patching=WAF/IPS rules as temp fix. Bug bounty=paying researchers. Always responsible disclosure first.",
     tech:"Zero-day: Vulnerability unknown to vendor, no patch available. Zero-day exploit: Active exploitation of a zero-day vulnerability in the wild. Zero-day attack: Attack using a zero-day exploit against targets. Lifecycle: Vulnerability exists → Discovered by researcher or attacker → If attacker: exploited before vendor knows (zero-day window) → Vendor learns → Patch developed → Patch released → Users apply patch. The window between discovery by attacker and patch deployment is the maximum risk period. Detection: Behavioral analysis (anomaly detection, not signatures), sandboxing, heuristic analysis, threat intelligence. Mitigation (without patch): Virtual patching (WAF/IPS rules blocking exploit pattern), micro-segmentation, enhanced monitoring, application allow-listing, principle of least privilege. Value: Zero-day exploits are extremely valuable — sold on black markets ($50K-$2.5M depending on target) or through bug bounty programs (legitimate disclosure). Responsible disclosure: Researcher notifies vendor, provides time window to patch before public disclosure.",
     terms:["Zero-day vulnerability","Zero-day exploit","Zero-day window","Virtual patching","Bug bounty","Responsible disclosure","Behavioral analysis"],
     tasks:["Research a recent zero-day that was actively exploited before patching","Compare bug bounty payouts across different platforms (HackerOne, Bugcrowd)","Explain why signature-based detection cannot catch zero-days"]},
   ],
   questions:[
    {q:"Unsanitized user input directly concatenated into a database query is vulnerable to:",o:["XSS","SQL injection","Buffer overflow","CSRF"],a:1,x:"Unsanitized input in SQL queries = textbook SQL injection vulnerability.",d:1},
    {q:"An attacker exploits a hypervisor vulnerability to access data from other VMs on the same host:",o:["Privilege escalation","VM escape","Container breakout","Resource reuse"],a:1,x:"VM escape breaks out of guest VM to hypervisor, potentially accessing other VMs.",d:2},
    {q:"The SolarWinds Orion attack where malicious code was distributed via a legitimate update is classified as:",o:["Zero-day exploit","Watering hole","Supply chain attack","Trojan horse"],a:2,x:"Supply chain attacks compromise the development/distribution pipeline of trusted software.",d:2},
    {q:"A vulnerability that the software vendor is unaware of with no available patch is a:",o:["Unpatched vulnerability","Logic bomb","Zero-day vulnerability","Race condition"],a:2,x:"Zero-day = unknown to vendor, zero days to prepare a fix.",d:1},
    {q:"XSS where the malicious script is permanently stored in the target's database and executes for every visitor is:",o:["Reflected XSS","Stored/Persistent XSS","DOM-based XSS","CSRF"],a:1,x:"Stored XSS is the most dangerous — payload persists in the database and executes for all visitors.",d:2},
    {q:"Removing manufacturer security restrictions on an iOS device is called:",o:["Rooting","Jailbreaking","Sideloading","Carrier unlocking"],a:1,x:"Jailbreaking = iOS. Rooting = Android. Both remove security restrictions.",d:1},
   ]},
  {id:"2.4",title:"Given a scenario, analyze indicators of malicious activity",
   topics:[
    {id:"2.4.1",title:"Malware",
     plain:"Malware is software designed to harm. A virus needs a host file (like a parasite needing an animal). A worm spreads on its own without help. A Trojan is a gift-wrapped bomb that looks legitimate. Ransomware kidnaps your files and demands payment. A rootkit hides DEEP in your system, like a spy who replaced your house's foundation. Fileless malware lives only in memory and uses your own system tools against you.",
     examTip:"Virus needs host. Worm self-replicates. Trojan disguises. Ransomware encrypts. Rootkit hides at kernel. Fileless=memory only.",
     tech:"Viruses: Require host file to propagate. Types: Boot sector (infects MBR/boot sector — runs before OS), Macro (embedded in Office documents — VBA), Polymorphic (changes code each replication to evade signatures), Metamorphic (completely rewrites itself), Fileless (no file on disk — uses PowerShell, WMI, legitimate tools, lives in memory). Worms: Self-propagate across networks without user interaction, exploit network vulnerabilities, consume bandwidth. Trojans: Disguised as legitimate software. RAT (Remote Access Trojan — full remote control), Banking Trojan (credential theft), Downloader (retrieves additional malware). Ransomware: Crypto-ransomware (encrypts files), Locker (locks system access). Double extortion: encrypt + exfiltrate + threaten to publish. Triple extortion: adds DDoS threat or targets victims' customers. Spyware: Monitors activity — keyloggers, screen capture, clipboard hijacking, browser history. Adware: Unwanted advertisements, may include tracking. Rootkits: Hide at kernel level (most dangerous), user level, or firmware level. Extremely difficult to detect/remove, may require full system rebuild. Logic bombs: Malicious code triggered by condition (date, user action, system event). Bloatware: Pre-installed unwanted software consuming resources.",
     terms:["Virus","Worm","Trojan","RAT","Ransomware","Spyware","Rootkit","Logic bomb","Polymorphic","Fileless malware","Double extortion","Bloatware"],
     tasks:["Research a real ransomware variant and map its complete kill chain","Set up a malware analysis sandbox with REMnux or FlareVM","Explain why fileless malware is harder to detect than traditional malware"]},
    {id:"2.4.2",title:"Password Attacks",
     plain:"Brute force = trying every possible combination (slow but guaranteed eventually). Dictionary attack = trying common words and passwords. Password spraying = trying ONE password against MANY accounts (avoids lockout). Credential stuffing = taking leaked passwords from one breach and trying them on other sites. Rainbow table = pre-computed hash lookup table.",
     examTip:"Brute force=try all. Dictionary=common words. Spraying=one password many accounts. Stuffing=leaked creds other sites. Kerberoasting=service tickets.",
     tech:"Brute force: Try every possible combination. Time depends on password length/complexity and computing power (GPU acceleration, cloud computing). Dictionary attack: Use wordlists of common passwords and variations. Hybrid: combine dictionary words with numbers/symbols. Password spraying: Try one or few passwords (Spring2024!, Company123) against many accounts. Stays under lockout thresholds. Effective against organizations with weak password policies. Credential stuffing: Use credentials leaked from other breaches — exploits password reuse. Automated tools test millions of credential pairs. Rainbow tables: Pre-computed hash→password lookup tables. Defeats unsalted hashes instantly. Prevention: salted hashing. Pass the hash: Use stolen NTLM hash to authenticate without knowing the password. Kerberoasting: Request Kerberos service tickets, crack offline for service account passwords. Prevention: Strong passwords, MFA, account lockout policies, password complexity requirements, credential monitoring services (Have I Been Pwned), salted hashing (bcrypt, Argon2).",
     terms:["Brute force","Dictionary attack","Password spraying","Credential stuffing","Rainbow table","Pass the hash","Kerberoasting","Salt","Account lockout"],
     tasks:["Use Hashcat to crack sample password hashes (educational only)","Research credential stuffing prevention techniques","Explain why password spraying is effective against enterprises"]},
    {id:"2.4.3",title:"Network Attacks",
     plain:"DDoS = a million people blocking a store entrance so real customers can't get in. DoS is just one person doing it. There are different flavors: volumetric (flood the connection), protocol (exploit how networks communicate), application (overwhelm the web server with seemingly normal requests).",
     examTip:"DDoS: volumetric (flood), protocol (SYN flood), application (HTTP/Slowloris). Amplification=DNS/NTP multiply traffic.",
     tech:"DoS/DDoS categories: Volumetric (bandwidth exhaustion — UDP flood, ICMP flood, DNS amplification, NTP amplification; measured in Gbps), Protocol (exploit protocol behavior — SYN flood: send SYN packets, never complete handshake, exhaust connection table; Smurf: ICMP broadcast with spoofed source), Application layer (target L7 — HTTP flood, Slowloris: keep many connections open with incomplete headers; harder to distinguish from legitimate traffic). Botnets: Networks of compromised devices (IoT especially) controlled by attacker for DDoS. Amplification attacks: Small request → large response directed at victim (DNS amplification ratio up to 50:1). Mitigation: Rate limiting, CDN/WAF (Cloudflare, Akamai), blackhole routing, SYN cookies, geographic filtering, auto-scaling, ISP coordination.",
     terms:["DoS","DDoS","SYN flood","Slowloris","Amplification","Botnet","Volumetric","Protocol","Application layer","Smurf attack","Rate limiting"],
     tasks:["Simulate SYN flood on a lab target using hping3 and observe impact","Research DNS amplification attack mechanics","Configure basic DDoS mitigation on a test web server"]},
    {id:"2.4.4",title:"DNS Attacks",
     plain:"DNS poisoning = someone changing all the road signs so you end up at a fake bank instead of the real one, and you don't know the difference. Domain hijacking = someone steals your address and redirects all your mail. DNS tunneling = smuggling data out through DNS queries, like hiding secret messages in mundane-looking postcards.",
     examTip:"DNS poisoning=corrupt cache. DNS tunneling=hide C2 in DNS. DNSSEC=sign records. Pharming=redirect via DNS.",
     tech:"DNS poisoning/spoofing: Injecting false DNS records into resolver cache. Victim queries DNS → receives attacker's IP → connects to malicious server. Can be cache-level or at the resolver. Domain hijacking: Compromising domain registrar account to modify DNS records, transfer domain, or redirect traffic. Requires social engineering registrar or compromising credentials. DNS tunneling: Encoding data in DNS queries and responses to exfiltrate data or establish C2 (command and control) channels. DNS traffic often allowed through firewalls without inspection. URL hijacking: Typosquatting + pharming. Pharming: Redirect traffic by modifying hosts file or DNS configuration. DNSSEC (DNS Security Extensions): Digitally signs DNS records to verify authenticity. Prevents cache poisoning. Adds RRSIG, DNSKEY, DS records. Does NOT encrypt queries (that's DoH/DoT). DNS filtering: Block known-malicious domains. Pi-hole, corporate DNS filtering.",
     terms:["DNS poisoning","Domain hijacking","DNS tunneling","DNSSEC","Pharming","DNS filtering","C2 channel"],
     tasks:["Configure DNSSEC on a test domain","Set up Pi-hole and analyze blocked DNS queries","Research DNS tunneling tools and detection methods"]},
    {id:"2.4.5",title:"Wireless Attacks",
     plain:"Evil twin = a fake WiFi access point that looks identical to the real one but has a stronger signal. You connect to it thinking it's legitimate, and the attacker sees everything you do. Deauth attack = forcefully disconnecting you from real WiFi to capture your reconnection attempt. RF jamming = blasting noise on the radio frequency so nobody can use WiFi.",
     examTip:"Evil twin=fake AP same SSID. Deauth=disconnect to capture handshake. Bluesnarfing=Bluetooth theft. 802.11w=protected management frames.",
     tech:"Evil twin: Rogue AP configured to mimic legitimate AP (same SSID). Often with stronger signal to attract victims. All traffic passes through attacker → MitM. Prevention: 802.1X/EAP authentication, WIDS (Wireless Intrusion Detection), VPN, user awareness. Deauthentication attack: Send forged deauth frames (exploiting 802.11 management frames are unencrypted in WPA2). Forces client to disconnect and reconnect → capture WPA2 4-way handshake → offline crack. Prevention: WPA3 (protected management frames), 802.11w. Rogue access point: Unauthorized AP connected to network — employee plugs in personal AP, creating backdoor. Prevention: NAC, WIDS, regular wireless scans. RF jamming: DoS by broadcasting interference on WiFi frequencies. Illegal but difficult to prevent technically. Bluetooth attacks: Bluesnarfing (unauthorized data access), Bluejacking (unsolicited messages), Bluebugging (remote control). WPS attacks: WiFi Protected Setup PIN can be brute-forced (8-digit PIN, only 11,000 combinations). Prevention: Disable WPS. Disassociation: Similar to deauth but targets AP-to-client communication.",
     terms:["Evil twin","Deauthentication","Rogue AP","RF jamming","Bluesnarfing","WPS brute force","802.11w","WIDS"],
     tasks:["Set up a WIDS to detect rogue APs in your environment","Research the WPA2 KRACK vulnerability and WPA3 improvements","Perform a wireless site survey and identify unauthorized access points"]},
    {id:"2.4.6",title:"On-path (Man-in-the-Middle) Attacks",
     plain:"An on-path attack is like a postal worker who opens your mail, reads it, maybe changes it, then reseals it and delivers it. Neither you nor the recipient knows someone was in the middle. ARP poisoning makes the network think the attacker IS the router, so all traffic flows through them.",
     examTip:"On-path/MitM: ARP poisoning at L2, SSL stripping at L7. Fix: encryption, HSTS, cert pinning, DNSSEC.",
     tech:"On-path/MitM attack: Attacker positions between two communicating parties, intercepting and potentially modifying traffic. ARP poisoning/spoofing: Send gratuitous ARP packets claiming attacker's MAC address maps to the gateway's IP. All traffic meant for gateway goes through attacker. Prevention: Dynamic ARP Inspection (DAI), static ARP entries, 802.1X. SSL/TLS interception: Attacker presents own certificate to victim, proxies connection to real server. Succeeds if victim ignores certificate warnings or attacker has compromised CA certificate. Prevention: Certificate pinning, HSTS, user awareness of certificate warnings. IP spoofing: Forge source IP address to impersonate trusted host. Browser-based: Injecting JavaScript to capture credentials in browser. Indicators: Certificate warnings, unexpected redirects, degraded performance, unusual DNS responses. Prevention: Encryption (TLS), certificate validation, HSTS preloading, network segmentation, ARP inspection, DNSSEC.",
     terms:["On-path/MitM","ARP poisoning","SSL stripping","IP spoofing","Dynamic ARP Inspection","HSTS","Certificate warning"],
     tasks:["Demonstrate ARP poisoning in a lab with Ettercap or arpspoof","Capture and analyze ARP traffic in Wireshark","Configure HSTS on a test web server and explain how it prevents downgrade attacks"]},
    {id:"2.4.7",title:"Replay and Other Attacks",
     plain:"A replay attack is like recording someone saying 'Open the gate' and playing the recording back later to open the gate yourself. The system hears a valid command but doesn't know it's a replay. Prevention: add timestamps and one-time-use codes so the same message can't work twice.",
     examTip:"Replay=resend captured data. Fix: timestamps, nonces. Birthday=hash collisions. Downgrade=force weaker protocol. Priv esc: vertical or horizontal.",
     tech:"Replay attacks: Capture and retransmit valid authentication tokens, session cookies, or network packets. Prevention: Timestamps (reject if too old), nonces (number used once — unique per request), session tokens with expiration, sequence numbers, challenge-response protocols. Cryptographic attacks: Birthday attack (find two inputs producing same hash — collision, exploits birthday paradox), Downgrade attack (force older/weaker protocol — POODLE forced SSL 3.0, Logjam forced weak DH), Known plaintext (attacker has both plaintext and ciphertext samples), Chosen ciphertext, Brute force against encryption. Physical attacks: Tailgating, Shoulder surfing, Dumpster diving, USB data theft, Device theft, Card skimming/cloning, RFID cloning, Malicious USB (Rubber Ducky). Application attacks: Privilege escalation (vertical: user→admin, horizontal: user→different user), API attacks (injection, broken authentication, excessive data exposure), Cross-site scripting, Request forgery.",
     terms:["Replay attack","Nonce","Timestamp","Birthday attack","Downgrade attack","Privilege escalation","Vertical","Horizontal","Known plaintext"],
     tasks:["Research the POODLE and Logjam downgrade attacks","Explain the birthday paradox and how it applies to hash collisions","Design authentication that prevents replay attacks"]},
    {id:"2.4.8",title:"Indicators of Malicious Activity",
     plain:"Indicators of Compromise (IoCs) are the digital fingerprints attackers leave behind — like muddy footprints from a burglar. Unexpected outbound connections to foreign countries at 3AM, new admin accounts nobody created, disabled antivirus, encrypted traffic to unknown servers — these are all red flags.",
     examTip:"IoCs: hashes, IPs, domains, beaconing. STIX=format. TAXII=transport. YARA=rules for malware identification.",
     tech:"Network indicators: Unexpected outbound connections (especially to known-bad IPs/countries), unusual traffic patterns, bandwidth spikes, DNS queries to suspicious domains, beaconing (regular interval callbacks to C2), port scanning detected, lateral movement between internal hosts. Host indicators: New/modified files in system directories, unexpected scheduled tasks/cron jobs, registry modifications, new user accounts, disabled security tools, modified log files, unexpected services/processes, unusual CPU/memory usage, autostart changes. Application indicators: Failed login attempts (brute force), impossible travel (logins from geographically distant locations in short time), privilege escalation attempts, SQL error messages in logs, unusual API calls, data exfiltration patterns (large outbound transfers). IoC types: File hashes (MD5/SHA-256 of known malware), IP addresses, domain names, URLs, email addresses, registry keys, mutex names, YARA rules. IoC sharing: STIX (Structured Threat Information eXpression) format, TAXII (Trusted Automated eXchange of Intelligence Information) protocol, OpenIOC. Threat intelligence platforms: MISP, AlienVault OTX, VirusTotal.",
     terms:["IoC","Beaconing","Lateral movement","C2","Impossible travel","STIX","TAXII","YARA","Threat intelligence","VirusTotal"],
     tasks:["Analyze sample SIEM alerts and identify IoCs","Research VirusTotal and analyze a suspicious file hash","Create an IoC response playbook for common indicator types"]},
   ],
   questions:[
    {q:"Thousands of login attempts using the SAME password against hundreds of different accounts indicates:",o:["Brute force","Dictionary attack","Password spraying","Credential stuffing"],a:2,x:"Password spraying = one password across many accounts to avoid lockout thresholds.",d:2},
    {q:"Malware operating entirely in RAM, using PowerShell, leaving no files on disk is:",o:["Rootkit","Virus","Fileless malware","Logic bomb"],a:2,x:"Fileless malware operates in memory using legitimate system tools.",d:2},
    {q:"Employee connects to 'Company_WiFi_Free' with stronger signal than legitimate 'Company_WiFi':",o:["Honeypot","Evil twin","Deauth attack","Rogue RADIUS"],a:1,x:"Evil twin mimics legitimate AP with stronger signal to lure victims.",d:1},
    {q:"A protocol that digitally signs DNS records to prevent cache poisoning is:",o:["HTTPS","DNSSEC","DoH","IPSec"],a:1,x:"DNSSEC signs DNS records to verify authenticity, preventing poisoning.",d:2},
    {q:"Regular interval network callbacks from an infected host to an attacker's server are called:",o:["Port scanning","Lateral movement","Beaconing","Exfiltration"],a:2,x:"Beaconing = regular check-in from compromised host to C2 server.",d:2},
    {q:"Using leaked credentials from one breach to access accounts on other services exploits:",o:["Weak passwords","Password reuse (credential stuffing)","Default credentials","Brute force"],a:1,x:"Credential stuffing exploits users reusing the same password across multiple services.",d:1},
   ]},
  {id:"2.5",title:"Explain the purpose of mitigation techniques",
   topics:[
    {id:"2.5.1",title:"Segmentation and Access Control",
     plain:"Segmentation splits your network into zones like rooms in a building — even if an attacker gets into one room, locked doors prevent access to others. A DMZ is the lobby where visitors are allowed, but they can't enter the offices. ACLs are the lists on each door saying who can enter.",
     examTip:"Segmentation limits blast radius. DMZ=screened subnet. Micro-segmentation=per-workload. Air gap=complete physical isolation.",
     tech:"Network segmentation: VLANs (logical separation at Layer 2), subnets (Layer 3 separation), micro-segmentation (granular, often identity-based — zero trust approach). DMZ (Demilitarized Zone): Network zone between external and internal networks for public-facing services. Screened subnet architecture. Access Control Lists (ACLs): Rules defining allowed/denied traffic. Network ACLs (router/firewall — source/dest IP, port, protocol), File system ACLs (NTFS permissions, Linux file permissions). Application allow-listing: Only pre-approved applications can execute. More restrictive than deny-listing (blocking known-bad). Group policies, AppLocker, application control. Isolation: Complete separation of critical systems — air gap (no network connection), separate physical networks. Used for SCADA/ICS, classified systems.",
     terms:["VLAN","Segmentation","DMZ","Micro-segmentation","ACL","Allow-listing","Deny-listing","Isolation","Air gap"],
     tasks:["Design a segmented network with DMZ, internal VLAN, and management VLAN","Configure VLANs on a managed switch","Compare application allow-listing vs deny-listing approaches"]},
    {id:"2.5.2",title:"Mitigation Techniques",
     plain:"Patching is like fixing a hole in your roof before it rains. Hardening is removing everything unnecessary — every extra window, door, or vent is a potential entry point. Least privilege means giving people only the minimum access they need — the janitor gets keys to the closet, not the vault.",
     examTip:"Critical patch=24-48hrs. When cant patch: virtual patching, compensating controls, enhanced monitoring. Document risk acceptance.",
     tech:"Patching: Regular update cycle with SLAs (Critical: 24-48hrs, High: 7 days, Medium: 30 days, Low: 90 days). Virtual patching via WAF/IPS when vendor patch unavailable. Automated patch management. Hardening: Remove unnecessary services/applications/ports, disable default accounts, change default passwords, implement secure configurations (CIS benchmarks, DISA STIGs), disable USB where not needed, implement host firewall, enable audit logging. Encryption: At rest (FDE), in transit (TLS), in use (enclaves). Monitoring: Continuous logging → SIEM correlation → alerting → response. Baseline establishment and drift detection. Least privilege: JIT (Just-In-Time) access, PAM (Privileged Access Management), no permanent admin rights, role-based access, regular access reviews. Configuration enforcement: Group Policy, MDM, configuration management tools — prevent configuration drift. Updates and firmware: Apply to all devices including network equipment, IoT, embedded systems.",
     terms:["Patching","Hardening","Least privilege","JIT access","PAM","CIS benchmarks","DISA STIGs","Virtual patching","Configuration enforcement"],
     tasks:["Harden a Linux VM following CIS Level 1 Benchmark","Create a patch management policy document with severity-based SLAs","Design a network with proper segmentation including DMZ, server VLAN, user VLAN, management VLAN"]},
   ],
   questions:[
    {q:"Web servers in a separate zone accessible from internet but isolated from internal LAN is a:",o:["VLAN","DMZ","VPN","Subnet"],a:1,x:"DMZ isolates public-facing services while allowing controlled access from both internet and internal network.",d:1},
    {q:"After critical vulnerability announced but before patch available, adding WAF rule to block exploit pattern is:",o:["Compensating control/virtual patching","Corrective control","Risk acceptance","Incident response"],a:0,x:"Virtual patching = WAF/IPS rules as compensating control while awaiting vendor patch.",d:3},
    {q:"Only allowing pre-approved software to run on endpoints is:",o:["Antivirus","Application allow-listing","Sandboxing","DLP"],a:1,x:"Application allow-listing only permits pre-approved executables, blocking everything else.",d:1},
   ,{q:"APTs are MOST associated with:",o:["Hacktivists","Nation-state actors","Script kiddies","Insider threats"],a:1,x:"APTs are nation-state sponsored with unlimited resources.",d:1},{q:"Employee installs unauthorized cloud storage:",o:["Social engineering","Shadow IT","Insider threat","Supply chain"],a:1,x:"Shadow IT = unauthorized tech without IT knowledge.",d:1},{q:"CEO email to CFO requesting $500K wire:",o:["Phishing","Spear phishing","BEC","Smishing"],a:2,x:"BEC targets executives with fraudulent wire transfer requests.",d:2},{q:"Everyone already provided credentials — which principle?",o:["Authority","Scarcity","Social proof","Intimidation"],a:2,x:"Social proof — people follow what others supposedly did.",d:1},{q:"SSRF targets cloud metadata at:",o:["127.0.0.1","10.0.0.1","169.254.169.254","192.168.1.1"],a:2,x:"Cloud metadata at 169.254.169.254 is primary SSRF target.",d:2},{q:"TOCTOU is a type of:",o:["Buffer overflow","Race condition","SQL injection","XSS"],a:1,x:"Time of Check to Time of Use — state changes between check and action.",d:2},{q:"SolarWinds attack type:",o:["Zero-day","Supply chain compromise","Phishing","DDoS"],a:1,x:"Attackers compromised the build process, distributing malware via updates.",d:1},{q:"Encrypt files AND threaten to publish stolen data:",o:["Single extortion","Double extortion","Triple extortion","Crypto-locking"],a:1,x:"Double extortion = encrypt + threaten leak.",d:1},{q:"One password against 10,000 accounts:",o:["Brute force","Dictionary","Password spraying","Credential stuffing"],a:2,x:"Password spraying avoids lockout thresholds.",d:1},{q:"NTP amplification is which DDoS type?",o:["Application","Protocol","Volumetric","Slowloris"],a:2,x:"Amplification floods with massive traffic — volumetric.",d:2},{q:"ARP poisoning prevented by:",o:["WPA3","DAI","DNSSEC","IPSec"],a:1,x:"Dynamic ARP Inspection validates ARP against DHCP snooping table.",d:2},{q:"Stolen credentials from breach tried on other sites:",o:["Password spraying","Brute force","Credential stuffing","Rainbow table"],a:2,x:"Credential stuffing exploits password reuse with leaked credentials.",d:1},{q:"POODLE forcing weaker protocol is a:",o:["Replay","Birthday","Downgrade","On-path"],a:2,x:"Downgrade attacks force use of weaker protocol versions.",d:2},{q:"IoC sharing in JSON format:",o:["TAXII","CVE","STIX","CVSS"],a:2,x:"STIX uses JSON. TAXII is the transport for STIX data.",d:1},{q:"Best mitigation for privilege escalation:",o:["Antivirus","Least privilege","Full disk encryption","Segmentation"],a:1,x:"Least privilege limits what a compromised account can access.",d:1},{q:"WAF rule while vendor develops patch:",o:["Permanent fix","Virtual patching","Risk acceptance","Risk transfer"],a:1,x:"Virtual patching blocks exploits when actual patches unavailable.",d:2},{q:"arnazon.com is:",o:["Phishing","Pharming","Typosquatting","DNS poisoning"],a:2,x:"Typosquatting = domains with slight misspellings.",d:1},{q:"SIM swapping targets:",o:["Hardware tokens","Biometrics","SMS MFA","Authenticator apps"],a:2,x:"SIM swapping redirects phone number to intercept SMS codes.",d:1},{q:"Polymorphic malware changes its:",o:["Payload","Code signature","Target","Protocol"],a:1,x:"Changes signature via mutation while keeping same payload.",d:2},{q:"Compromised trusted website attack:",o:["Spear phishing","Watering hole","Drive-by","Evil twin"],a:1,x:"Watering hole compromises websites the target group frequents.",d:2}]},
]},
  {
  id:3, title:"Security Architecture", weight:18, icon:"🏗️", color:"#ffa502",
  objectives:[
  {id:"3.1",title:"Compare and contrast security implications of different architecture models",
   topics:[
    {id:"3.1.1",title:"Cloud Models",
     plain:"IaaS = renting an empty apartment (bring your own furniture/OS/apps). PaaS = furnished apartment (kitchen/runtime ready, just cook/code). SaaS = hotel (everything done for you). Shared responsibility: the cloud provider secures the building, you secure your room. The more 'as-a-service' you get, the less you manage but the less control you have.",
     examTip:"IaaS=you manage OS up. PaaS=app/data. SaaS=provider manages all. Shared responsibility shifts per model.",
     tech:"IaaS (Infrastructure): Customer manages OS/apps/data, provider manages hardware/virtualization/networking (AWS EC2, Azure VMs, GCP Compute). PaaS (Platform): Customer manages apps/data, provider manages OS/runtime/middleware (Heroku, Azure App Service, Google App Engine, Elastic Beanstalk). SaaS (Software): Provider manages everything, customer configures (Microsoft 365, Salesforce, Google Workspace). XaaS: Anything as a service (DaaS, SECaaS, IaaS). Deployment: Public (multi-tenant, shared infrastructure), Private (dedicated, single org), Hybrid (combination, sensitive workloads stay private), Community (shared by orgs with common needs — government), Multi-cloud (multiple providers, avoid lock-in). Shared responsibility: Security OF the cloud (provider physical/hypervisor) vs Security IN the cloud (customer data/identity/apps). Varies by model — IaaS most customer responsibility, SaaS least.",
     terms:["IaaS","PaaS","SaaS","XaaS","Public cloud","Private cloud","Hybrid cloud","Multi-cloud","Shared responsibility"],
     tasks:["Diagram shared responsibility model for each cloud type","Deploy a simple app on each model to understand differences","Audit a cloud storage bucket for public access misconfigurations"]},
    {id:"3.1.2",title:"Serverless and Microservices",
     plain:"Serverless = you write code, the cloud runs it only when needed, and you pay only for execution time. Like hiring a chef who only shows up when you order food instead of keeping them on salary. Microservices = instead of one giant restaurant, you have separate food trucks for pizza, sushi, and tacos — each independent, each scalable.",
     examTip:"Serverless=FaaS, event-driven. Microservices use APIs. Service mesh handles mTLS between services automatically.",
     tech:"Serverless/FaaS (Function as a Service): Event-driven compute — code runs in response to triggers (HTTP request, database change, schedule). Ephemeral containers — spin up, execute, terminate. Examples: AWS Lambda, Azure Functions, Google Cloud Functions. Benefits: No server management, auto-scaling, pay-per-execution. Security concerns: Function injection (through event data), excessive permissions (overly permissive IAM roles), vulnerable dependencies (outdated packages), cold start data exposure, lack of traditional network controls. Microservices: Application decomposed into independent services communicating via APIs. Each service independently deployable, scalable, maintainable. Security: API gateway for authentication/rate limiting, service mesh (mTLS between services — Istio, Linkerd), container security, service-to-service authentication.",
     terms:["Serverless","FaaS","Microservices","API gateway","Service mesh","Event-driven","Container","Lambda"],
     tasks:["Deploy a serverless function on AWS Lambda or Azure Functions","Research API gateway security features","Compare monolithic vs microservices architecture security trade-offs"]},
    {id:"3.1.3",title:"Infrastructure as Code",
     plain:"IaC is writing a recipe for your entire infrastructure so you can rebuild it identically anytime. Instead of manually configuring 100 servers by clicking buttons, you write code that does it automatically. If a server is compromised, destroy it and rebuild from the recipe in minutes.",
     examTip:"Terraform/CloudFormation=IaC. Immutable=replace dont patch. Drift detection finds unauthorized changes.",
     tech:"IaC: Define infrastructure through code/configuration files, version-controlled, repeatable, auditable. Tools: Terraform (multi-cloud, declarative HCL), AWS CloudFormation, Azure ARM/Bicep, Pulumi. Benefits: Consistency (identical environments), speed (rapid provisioning), auditability (version-controlled changes), disaster recovery (rebuild from code). Security: IaC scanning (Checkov, Terrascan, tfsec — detect misconfigurations before deployment), secrets management (never hardcode credentials in IaC — use vault/secrets manager), least privilege for deployment pipelines, immutable infrastructure (replace rather than modify), drift detection (alert when actual state differs from code).",
     terms:["IaC","Terraform","CloudFormation","Immutable infrastructure","IaC scanning","Secrets management","Drift detection"],
     tasks:["Write a basic Terraform configuration for a VM with security group","Scan IaC templates with Checkov for security issues","Explain immutable infrastructure and its security benefits"]},
    {id:"3.1.4",title:"Centralized vs Decentralized Architectures",
     plain:"Centralized = one big bank vault (easier to protect but single point of failure). Decentralized = multiple smaller safes spread across locations (harder to protect all of them but more resilient). Each has trade-offs in security, availability, and management complexity.",
     examTip:"SASE=SD-WAN+cloud security (CASB+FWaaS+SWG+ZTNA). Edge computing processes near source. Know SASE components.",
     tech:"Centralized: Single control point for management, monitoring, policy enforcement. Easier to secure and audit. Risk: single point of failure, attractive target. Examples: On-premises data center, centralized SIEM, centralized identity provider. Decentralized: Distributed across locations/systems, no single authority. More resilient (no single point of failure), harder to manage/secure consistently. Examples: Blockchain, edge computing, CDN, distributed databases. SD-WAN (Software-Defined WAN): Centralized control plane managing distributed WAN connections — intelligently routes traffic across multiple connection types (MPLS, broadband, LTE). Simplifies branch office networking. SASE (Secure Access Service Edge): Combines SD-WAN + cloud security services (CASB, FWaaS, SWG, ZTNA) into single cloud-delivered service. Gartner coined term. Converges networking and security.",
     terms:["Centralized","Decentralized","SD-WAN","SASE","CASB","FWaaS","SWG","ZTNA","Edge computing"],
     tasks:["Compare centralized vs decentralized architecture trade-offs","Research SASE vendors and their security service components","Explain how SD-WAN differs from traditional WAN"]},
    {id:"3.1.5",title:"Containerization",
     plain:"Containers are like shipping containers — standardized boxes that work the same everywhere. Each container holds an app with everything it needs, isolated from other containers. Much lighter than VMs because they share the host OS kernel instead of running separate operating systems.",
     examTip:"Containers share host kernel (less isolation than VMs). Kubernetes orchestrates. Image scanning before deployment. Escape=access host kernel.",
     tech:"Containers: Lightweight virtualization sharing host kernel. Docker (container runtime), Kubernetes (orchestration — manages container deployment, scaling, networking across clusters). Security: Container isolation (namespaces, cgroups — less isolation than VMs since shared kernel), Image security (scan images for vulnerabilities, use minimal base images like Alpine, sign images), Runtime security (read-only filesystem, drop unnecessary capabilities, no root), Registry security (private registries, image signing/trust), Orchestration security (RBAC in K8s, network policies, pod security standards, secrets management). Risks: Container escape (break out to host — more likely than VM escape), insecure images (embedded credentials, vulnerable packages), misconfigured orchestration (exposed dashboard, default service accounts).",
     terms:["Container","Docker","Kubernetes","Image scanning","Container escape","Namespace","Orchestration","Pod security"],
     tasks:["Build and scan a Docker container image for vulnerabilities","Deploy a simple K8s cluster and implement network policies","Compare container security vs VM security trade-offs"]},
    {id:"3.1.6",title:"Embedded Systems and IoT",
     plain:"IoT devices are everywhere - cameras, thermostats, medical devices, industrial sensors. The security nightmare: most ship with default credentials, many cannot be updated, limited CPU/memory prevents security software, and they often communicate in cleartext. SCADA/ICS systems control power grids, water treatment, and manufacturing. They use protocols like Modbus and DNP3, have 15-25 year lifecycles meaning they may run ancient operating systems, and must prioritize SAFETY over security. The primary defense for both IoT and SCADA is network segmentation - isolate them on separate VLANs where a compromised camera cannot reach patient records.",
     examTip:"For IoT/SCADA questions answer is almost always SEGMENTATION or ISOLATION. Cant patch? Cant run AV? Isolate on separate network segment.",
     tech:"IoT (Internet of Things): Devices with limited compute/memory, often real-time operating systems (RTOS). Security challenges: Default/hardcoded credentials, limited/no encryption, infrequent firmware updates, long lifecycles, legacy protocols, constrained resources (can't run traditional security tools), massive attack surface (billions of devices). Embedded systems: Purpose-built devices with firmware (medical devices, industrial controllers, smart appliances). Often run modified Linux or RTOS. SCADA (Supervisory Control and Data Acquisition) / ICS (Industrial Control Systems): Control physical processes — power plants, water treatment, manufacturing. Historically air-gapped but increasingly connected. Vulnerabilities: Legacy protocols (Modbus, DNP3 — no authentication), long lifecycle (15-25 years), limited patching, safety-critical. Mitigation: Network segmentation (separate IoT VLAN), change default credentials, disable unnecessary features, firmware updates, monitor traffic, vendor security requirements.",
     terms:["IoT","Embedded system","RTOS","SCADA","ICS","Modbus","Firmware","Air gap","Network segmentation"],
     tasks:["Scan your home network for IoT devices and assess their security","Research Shodan for exposed SCADA/ICS systems","Create an IoT security policy for a smart office"]},
   ],
   questions:[
    {q:"In IaaS, who is responsible for patching the guest OS?",o:["Cloud provider","Customer","Shared equally","Neither"],a:1,x:"IaaS: customer manages OS/apps/data, provider manages underlying infrastructure.",d:1},
    {q:"Using AWS + Azure simultaneously to avoid vendor dependency is:",o:["Hybrid cloud","Multi-cloud","Community cloud","Private cloud"],a:1,x:"Multi-cloud = services from multiple providers reducing vendor lock-in.",d:1},
    {q:"SASE combines SD-WAN with cloud-delivered security services including:",o:["RAID and backups","CASB, FWaaS, SWG, ZTNA","SIEM and SOAR","PKI and HSM"],a:1,x:"SASE converges networking (SD-WAN) with cloud security (CASB, FWaaS, SWG, ZTNA).",d:2},
    {q:"Scanning container images before deployment helps prevent:",o:["VM escape","Deploying vulnerable dependencies","Network congestion","Data remanence"],a:1,x:"Container image scanning identifies vulnerable packages and misconfigurations before deployment.",d:1},
   ]},
  {id:"3.2",title:"Apply security principles to secure enterprise infrastructure",
   topics:[
    {id:"3.2.1",title:"Network Security Infrastructure",
     plain:"A firewall is the bouncer at the door. NGFW is an advanced bouncer who checks IDs (packet headers), X-rays your bag (deep packet inspection), checks the watchlist (threat intelligence), AND reads your body language (behavioral analysis). Load balancers are like multiple lanes at a toll booth — distribute traffic so no single server gets overwhelmed.",
     examTip:"Firewall types: packet filter (stateless), stateful (tracks connections), NGFW (deep inspection), WAF (HTTP). IDS=detect. IPS=block inline.",
     tech:"Firewalls: Packet filter (L3/L4 — source/dest IP, ports), Stateful inspection (tracks connection states — new/established/related), NGFW (Next-Gen — DPI + application awareness + integrated IPS + threat intelligence feeds + SSL/TLS inspection + user identity awareness), WAF (Web Application Firewall — L7, protects against OWASP Top 10, SQLi, XSS), UTM (Unified Threat Management — all-in-one: firewall + AV + IDS + URL filter, for SMBs). IDS/IPS: Signature-based (pattern matching known attacks — fast, accurate, cannot detect unknown), Anomaly/behavioral-based (baseline normal → alert on deviations — catches zero-days, higher false positives), Heuristic (rule-based analysis). IDS = passive (detect/alert via SPAN port), IPS = inline (detect/block). Proxies: Forward (client → proxy → internet: anonymity, content filtering, caching), Reverse (internet → proxy → server: load distribution, SSL offloading, WAF, protection), Transparent (no client configuration needed). Load balancers: Distribute traffic across server pool, health checks, session persistence, SSL offloading. Jump server/bastion host: Hardened intermediary for admin access to secure zones. VPN concentrator. NAC (802.1X): Network Access Control — posture assessment before network access.",
     terms:["NGFW","WAF","UTM","IDS","IPS","Forward proxy","Reverse proxy","Load balancer","Jump server","NAC","802.1X","DPI"],
     tasks:["Configure pfSense firewall with Snort/Suricata IDS rules","Set up a reverse proxy with Nginx and configure SSL termination","Compare NGFW vendors: Palo Alto, Fortinet, Cisco"]},
    {id:"3.2.2",title:"Secure Communication and Access",
     plain:"A VPN is a private tunnel through the public internet — like a sealed pneumatic tube running through a busy street. No one outside can see what's inside. IPSec protects the tunnel itself. Site-to-site connects two offices. Remote access connects one person to the office.",
     examTip:"VPN: remote access vs site-to-site. IPSec: AH=integrity only, ESP=integrity+encryption. Tunnel mode=full packet, transport=payload only.",
     tech:"VPN types: Remote access (individual user → corporate network, SSL/TLS VPN or IPSec), Site-to-site (office → office, IPSec tunnel, always-on), Split tunnel (only corporate traffic through VPN, internet traffic direct — less secure but better performance), Full tunnel (ALL traffic through VPN — more secure). IPSec: AH (Authentication Header — integrity only, no encryption), ESP (Encapsulating Security Payload — encryption + integrity), IKE (Internet Key Exchange — negotiates security associations). Tunnel mode (encrypt entire packet) vs Transport mode (encrypt only payload). SD-WAN: Software-defined WAN, centralized control, multiple connection types, intelligent routing. Secure protocols table: SSH(22) replaces Telnet(23), SFTP/SCP replaces FTP(21), HTTPS(443) replaces HTTP(80), SNMPv3 replaces v1/v2c, LDAPS(636) replaces LDAP(389), IMAPS(993) replaces IMAP(143), SMTPS(587/465) replaces SMTP(25). Port security: 802.1X, MAC filtering (weak), DHCP snooping, dynamic ARP inspection.",
     terms:["VPN","IPSec","AH","ESP","IKE","Split tunnel","Full tunnel","Site-to-site","Remote access","Secure protocols"],
     tasks:["Set up OpenVPN server and configure both split and full tunnel","Create a table mapping all insecure protocols to secure alternatives with port numbers","Configure port security on a managed switch"]},
   ],
   questions:[
    {q:"Device placed inline to actively block malicious traffic in real-time:",o:["IDS","IPS","SIEM","Packet sensor"],a:1,x:"IPS is inline, actively blocks. IDS is passive, only detects/alerts.",d:1},
    {q:"A jump server's primary purpose is to:",o:["Balance load","Provide secure admin access to restricted zones","Filter web traffic","Store backups"],a:1,x:"Jump servers are hardened intermediaries for administrative access to sensitive zones.",d:2},
    {q:"IPSec ESP provides:",o:["Integrity only","Encryption + integrity","Routing only","DNS resolution"],a:1,x:"ESP (Encapsulating Security Payload) provides both encryption and integrity verification.",d:2},
    {q:"WAF specifically protects against:",o:["Wireless attacks","Web application attacks (OWASP Top 10)","WAN failures","Windows vulnerabilities"],a:1,x:"WAF = Web Application Firewall protecting against SQLi, XSS, and other OWASP Top 10 attacks.",d:1},
   ]},
  {id:"3.3",title:"Compare and contrast concepts and strategies to protect data",
   topics:[
    {id:"3.3.1",title:"Data Types and Classification",
     plain:"Data classification is like a hospital: visiting hours are public, staff schedules are internal, patient records are confidential, and experimental drug formulas are restricted/critical. Each level gets different locks, different access rules, and different handling procedures.",
     examTip:"Classification: Public, Internal, Confidential, Restricted. PII=personal info. PHI=health info. Data sovereignty=laws where data is stored.",
     tech:"Classification levels: Public (no impact if disclosed — marketing materials), Private/Internal (minimal impact — employee directory, org charts), Confidential/Sensitive (significant impact — financial records, PII, customer data), Critical/Restricted/Top Secret (severe impact — trade secrets, classified military, encryption keys). Regulated data types: PII (Personally Identifiable Information — name+SSN, name+DOB, email+password), PHI (Protected Health Information — HIPAA, medical records+identity), Financial (PCI-DSS — credit card numbers, bank accounts), Intellectual property (trade secrets, patents, proprietary code). Data sovereignty: Legal requirement that data is subject to laws of the country where it's stored. GDPR requires EU citizen data to stay in EU or in countries with adequate protections. Data states: At rest (storage), In transit (network), In use (memory/processing). Each requires different protection.",
     terms:["Data classification","PII","PHI","PCI-DSS","Data sovereignty","Public","Confidential","Restricted","Intellectual property"],
     tasks:["Create a data classification policy for a healthcare organization","Identify all PII/PHI in a sample database schema","Research data sovereignty requirements across 3 countries"]},
    {id:"3.3.2",title:"Data Protection Methods",
     plain:"DLP (Data Loss Prevention) is the security guard that checks everyone's bag when leaving the building — it watches for sensitive data being sent out via email, USB, or cloud. Tokenization replaces your real credit card number with a fake one that's useless to thieves. Rights management controls who can read, copy, print, or forward a document.",
     examTip:"DLP monitors three data states. Tokenization preserves format. Masking for non-production. DRM restricts copy/print/forward.",
     tech:"DLP (Data Loss Prevention): Network DLP (monitors traffic at gateway — email, web, FTP), Endpoint DLP (agent on device — block USB copy, screen capture, clipboard), Cloud DLP (monitors cloud storage/SaaS). Detection methods: pattern matching (regex for SSN, credit card), keyword matching, fingerprinting (exact data match), classification tags. Tokenization: Replace sensitive data with random token. Token vault maps token→original. Unlike encryption: token has NO mathematical relationship to original, cannot be reversed without vault. Common for PCI-DSS compliance. Data masking: Obfuscate data for non-production environments. Static (permanent transformation), Dynamic (real-time, role-based). Techniques: substitution, shuffling, nulling, character scrambling. Rights management (DRM/IRM): Control read/edit/copy/print/forward/expiration per document. Microsoft Purview/Azure Information Protection, Adobe DRM. Geographic restrictions: Geofencing data access.",
     terms:["DLP","Tokenization","Data masking","DRM/IRM","Token vault","Network DLP","Endpoint DLP","Geofencing"],
     tasks:["Compare tokenization vs encryption with specific use cases","Research Microsoft Purview Information Protection features","Design a DLP policy for a company handling credit card data"]},
   ],
   questions:[
    {q:"Replacing credit card numbers with random tokens in a test database is:",o:["Encryption","Tokenization","Data masking","Hashing"],a:1,x:"Tokenization replaces sensitive data with non-sensitive tokens. Unlike encryption, no mathematical relationship.",d:2},
    {q:"Degaussing destroys data on:",o:["SSDs","Magnetic media (HDDs/tapes)","Flash drives","Optical discs"],a:1,x:"Degaussing disrupts magnetic fields — works on HDDs and tapes, NOT on SSDs or flash.",d:2},
    {q:"DLP that monitors email and web traffic at the network gateway is:",o:["Endpoint DLP","Network DLP","Cloud DLP","Host DLP"],a:1,x:"Network DLP inspects traffic at the gateway before it leaves the network.",d:1},
   ]},
  {id:"3.4",title:"Explain the importance of resilience and recovery in security architecture",
   topics:[
    {id:"3.4.1",title:"High Availability and Redundancy",
     plain:"High availability means the system almost never goes down — like a hospital that can't close. Achieved through redundancy: if one component fails, another takes over. RAID spreads data across multiple disks. Clustering means multiple servers act as one. Load balancing distributes work so no single server is overwhelmed.",
     examTip:"RAID: 0=stripe, 1=mirror, 5=parity(1 fail), 6=double parity(2 fail), 10=mirror+stripe(best). Active-active vs active-passive.",
     tech:"Redundancy types: Server (clustering, active-active or active-passive failover), Network (dual ISPs, redundant switches/routers, NIC teaming/bonding), Storage (RAID, SAN replication), Power (dual power supplies, UPS, generators, PDUs), Geographic (multiple data centers in different regions). RAID levels: RAID 0 (striping — performance, NO redundancy), RAID 1 (mirroring — duplicate data, 50% capacity loss), RAID 5 (striping with parity — survives 1 drive failure, minimum 3 drives), RAID 6 (double parity — survives 2 failures), RAID 10 (mirror + stripe — performance + redundancy, 50% capacity). Load balancing: Round robin, least connections, weighted, IP hash. Health checks detect failed servers. Session persistence/sticky sessions. Fault tolerance vs High availability: Fault tolerance = zero downtime (instant failover), HA = minimal downtime (brief failover). Availability targets: 99.9% = 8.7 hours downtime/year, 99.99% = 52 minutes, 99.999% (five nines) = 5.3 minutes.",
     terms:["High availability","Redundancy","RAID","Clustering","Failover","Active-active","Active-passive","NIC teaming","UPS","Five nines"],
     tasks:["Set up RAID 1 and RAID 5 in VMs and test drive failure recovery","Calculate availability percentage for different SLA requirements","Design a highly available web application architecture diagram"]},
    {id:"3.4.2",title:"Backups",
     plain:"3-2-1 rule: 3 copies of your data, on 2 different types of media, with 1 copy offsite. Full backup = copying EVERYTHING (simplest restore, most storage). Incremental = only what changed since LAST backup (fastest, but restore needs entire chain). Differential = what changed since last FULL backup (middle ground). Immutable backups can't be deleted by ransomware.",
     examTip:"Full=everything. Incremental=since last ANY backup. Differential=since last FULL. Immutable/WORM=ransomware protection.",
     tech:"Backup types: Full (complete copy every time — simplest restore, most storage/time), Incremental (changes since last ANY backup — fastest backup, requires full chain for restore, if any link is corrupted restore fails), Differential (changes since last FULL — larger than incremental but restore needs only full + latest differential). 3-2-1 rule: 3 copies, 2 different media types (disk + tape, disk + cloud), 1 offsite location. Snapshot: Point-in-time copy, often at block level (VM snapshots, storage snapshots). Fast creation but dependent on source storage. Immutable backups: WORM (Write Once Read Many) — cannot be modified or deleted for specified retention period. Critical ransomware protection. Air-gapped backups: Physically disconnected backup media (tape vaults). Offsite/cloud: Geographic separation from primary site (natural disaster protection). Backup testing: Regular restore tests to verify backup integrity and procedure. Document RTO for restore process.",
     terms:["Full backup","Incremental","Differential","3-2-1 rule","Snapshot","Immutable/WORM","Air-gapped backup","Backup testing","Retention"],
     tasks:["Configure automated backups following the 3-2-1 rule","Test restoring from different backup types and measure time","Create a backup policy with retention schedules and testing requirements"]},
    {id:"3.4.3",title:"Resilience and Recovery Sites",
     plain:"RTO = how long you can survive without the system before the business suffers unacceptable damage. RPO = how much data you can afford to lose. Hot site = a fully furnished backup house you move into immediately. Warm site = partially equipped, takes hours. Cold site = an empty lot where you build from scratch in days/weeks.",
     examTip:"RTO=max downtime. RPO=max data loss. Hot=minutes. Warm=hours. Cold=days. DR tests: tabletop, simulation, parallel, full interruption.",
     tech:"Recovery metrics: RTO (Recovery Time Objective — maximum acceptable downtime before business impact), RPO (Recovery Point Objective — maximum acceptable data loss measured in time), MTTR (Mean Time To Repair — average time to restore service), MTBF (Mean Time Between Failures — average operational time between incidents). Site types: Hot (fully operational, real-time data replication, switchover in minutes — most expensive), Warm (partially equipped, servers available but data needs loading, activation in hours), Cold (empty facility with power/network, everything must be installed, days/weeks to activate — least expensive). Geographic considerations: Far enough from primary to avoid same disaster (different power grid, flood zone, seismic zone), close enough for reasonable network latency. Cloud DR: Multi-region deployment, auto-scaling, pilot light (minimal always-on resources that scale up during DR), warm standby. DR testing types: Tabletop exercise (walkthrough discussion), Simulation test (simulate without actual failover), Parallel processing (run DR systems alongside production), Full interruption test (actually fail over — most realistic but highest risk).",
     terms:["RTO","RPO","MTTR","MTBF","Hot site","Warm site","Cold site","Tabletop exercise","Pilot light","DR testing"],
     tasks:["Calculate RTO and RPO requirements for 5 different business scenarios","Create a disaster recovery plan template","Design DR architecture using cloud multi-region deployment"]},
    {id:"3.4.4",title:"Power Resilience",
     plain:"A UPS is a battery backup that keeps things running during a brief power outage — like a spare tire getting you to the mechanic. A generator is for long outages — like a rental car while yours is in the shop. PDUs distribute power to all equipment in a rack, and dual power supplies mean one can fail without taking the server down.",
     examTip:"Online UPS=zero transfer (servers). Line-interactive=milliseconds. Standby=cheapest. Generator needs ATS.",
     tech:"UPS (Uninterruptible Power Supply): Battery backup providing immediate power during outage. Types: Online/double-conversion (continuous battery power — cleanest, most expensive), Line-interactive (conditions power, switches to battery on failure), Standby/offline (switches to battery on failure — brief interruption). Provides time to gracefully shut down or for generator to start. Generator: Diesel or natural gas for extended outages. Automatic Transfer Switch (ATS) detects outage and starts generator. Takes 10-30 seconds to reach full power — UPS bridges the gap. PDU (Power Distribution Unit): Distributes power to equipment in rack. Managed PDUs allow remote monitoring/control of individual outlets. Dual power supplies: Servers with redundant PSUs connected to separate circuits/PDUs. One fails, other continues. Surge protector: Protects against voltage spikes. Power conditioning: Clean/stable power delivery, prevents brownouts and spikes.",
     terms:["UPS","Generator","PDU","Dual power supply","Online UPS","Surge protector","ATS"],
     tasks:["Calculate UPS runtime requirements for a server rack","Design a power resilience plan with UPS + generator + dual feeds","Research managed PDU features and remote management capabilities"]},
   ],
   questions:[
    {q:"Maximum 4 hours of acceptable data loss defines:",o:["RTO","RPO","MTTR","MTBF"],a:1,x:"RPO = maximum acceptable data loss measured in time. If RPO is 4 hours, backup must be no older than 4 hours.",d:1},
    {q:"Backup requiring MOST storage but simplest restore:",o:["Incremental","Differential","Full","Snapshot"],a:2,x:"Full backup copies everything each time. Restore requires only the latest full backup.",d:1},
    {q:"Protection against ransomware encrypting backup data:",o:["Differential backups","Immutable/WORM storage","RAID 6","Tape rotation"],a:1,x:"Immutable (WORM) backups cannot be modified or deleted, preventing ransomware encryption.",d:2},
    {q:"A DR site with servers present but requiring data loading before activation is:",o:["Hot site","Warm site","Cold site","Mobile site"],a:1,x:"Warm site is partially equipped — takes hours to activate as data must be loaded.",d:1},
    {q:"RAID 5 requires a minimum of how many drives?",o:["2","3","4","5"],a:1,x:"RAID 5 needs minimum 3 drives: data striped across all with distributed parity.",d:1},
   ,{q:"IaaS shared responsibility — OS patching:",o:["Provider","Customer","Shared","Neither"],a:1,x:"IaaS: customer manages OS and up. Provider manages hardware.",d:1},{q:"Serverless security concern:",o:["VM escape","OS patching","Function permission over-provisioning","Hypervisor vuln"],a:2,x:"Function IAM permissions can be over-provisioned by customer.",d:2},{q:"SCADA lifecycle:",o:["2-3 years","5-7 years","15-25 years","50+ years"],a:2,x:"SCADA/ICS run 15-25 years, making patching challenging.",d:1},{q:"Type 1 hypervisor runs on:",o:["Guest OS","Host OS","Bare-metal","Container"],a:2,x:"Type 1 bare-metal on hardware directly. Type 2 on host OS.",d:1},{q:"RAID 5 uses:",o:["Mirroring/2 drives","Distributed parity/3+ drives","No redundancy","Double parity/4+"],a:1,x:"RAID 5: distributed parity, survives 1 drive failure, min 3 drives.",d:2},{q:"3-2-1 backup rule:",o:["3 backups/2 sites/1 cloud","3 copies/2 media/1 offsite","3 incremental/2 diff/1 full","3 daily/2 weekly/1 monthly"],a:1,x:"3 copies, 2 different media, 1 offsite.",d:1},{q:"802.1X three components:",o:["Router/switch/server","Supplicant/authenticator/auth server","Firewall/IDS/proxy","Client/AP/DHCP"],a:1,x:"Supplicant (client), Authenticator (switch/AP), Auth server (RADIUS).",d:2},{q:"Split tunnel VPN:",o:["Encrypts all","Only corporate through VPN","IPSec only","Requires MFA"],a:1,x:"Only corporate traffic through VPN. Other direct to internet.",d:1},{q:"Online UPS provides:",o:["Surge protection","Zero transfer time","30ms switchover","No battery"],a:1,x:"Continuous AC→DC→AC conversion = zero transfer time.",d:2},{q:"FM-200 preferred because:",o:["Cheaper","No electronics damage","Lasts longer","Easier install"],a:1,x:"Clean agent suppresses fire without water damage to equipment.",d:1},{q:"Container escape compromises:",o:["App code","Image","Host OS kernel","Virtual network"],a:2,x:"Breaks namespace isolation to access host OS kernel.",d:2},{q:"Endpoint DLP monitors:",o:["Network","Cloud","USB/clipboard/print","Email gateway"],a:2,x:"Endpoint DLP controls data movement on the device itself.",d:1},{q:"Hot vs cold site difference:",o:["Location","Real-time replication+immediate availability","Internet","Physical security"],a:1,x:"Hot=replicated+ready in minutes. Cold=empty+days to activate.",d:1},{q:"Which cloud gives MOST customer control?",o:["SaaS","PaaS","IaaS","FaaS"],a:2,x:"IaaS: customer controls OS and up.",d:1},{q:"Immutable infrastructure means:",o:["Never updated","Replace instead of patch","Unhackable","Admin-only changes"],a:1,x:"Destroy and redeploy from clean image rather than patching in place.",d:2},{q:"SASE combines SD-WAN with:",o:["VPN","CASB+FWaaS+SWG+ZTNA","AV+firewall","Load balancer"],a:1,x:"SASE = SD-WAN + cloud security services.",d:2},{q:"RAID 10 combines:",o:["Stripe+parity","Mirror+stripe","Double parity","Triple mirror"],a:1,x:"RAID 10 = mirror first then stripe. Best performance and redundancy.",d:2},{q:"Differential backup = changes since:",o:["Last incremental","Last differential","Last full","Yesterday"],a:2,x:"Differential = changes since last FULL backup.",d:1},{q:"RPO of 1 hour means:",o:["Restored in 1hr","Max 1hr data loss","Backup runs 1hr","Test hourly"],a:1,x:"RPO = max acceptable data loss. Need backups at least hourly.",d:1},{q:"Tabletop exercise is:",o:["Full failover","Discussion-based scenario walkthrough","Parallel test","Pentest"],a:1,x:"Team discusses response to hypothetical scenarios. No systems affected.",d:1},{q:"WAF protects against:",o:["DDoS only","Layer 7 web attacks (SQLi/XSS)","Network scans","Physical intrusion"],a:1,x:"WAF inspects HTTP/HTTPS for SQL injection, XSS, other web attacks.",d:1},{q:"IDS vs IPS key difference:",o:["IDS is newer","IDS detects, IPS blocks inline","IPS is passive","Same thing"],a:1,x:"IDS = passive alerting. IPS = inline active blocking.",d:1},{q:"Bastion/jump server purpose:",o:["Load balancing","Single hardened admin access point","DNS","Backup"],a:1,x:"Heavily hardened and monitored entry point for server management.",d:2},{q:"Data sovereignty means:",o:["You own data","Data subject to laws where stored","Data undeletable","Government owns data"],a:1,x:"Data in EU is subject to GDPR regardless of company HQ location.",d:1},{q:"MTBF measures:",o:["Fix time","Average time between failures","Backup freq","Test baseline"],a:1,x:"Mean Time Between Failures. Higher = more reliable hardware.",d:2},{q:"Forward vs reverse proxy:",o:["Same","Forward=client side, reverse=server side","Forward=server","Forward=encrypted"],a:1,x:"Forward protects clients (filtering). Reverse protects servers (WAF/load balancing).",d:2},{q:"Pilot light DR:",o:["Minimal core infra running, scale when needed","Full hot site","Cold site","Tape backup"],a:0,x:"Minimal always-on infrastructure, scale up during disaster.",d:3},{q:"Geofencing in security:",o:["Physical fence","Restrict access by geographic location","Encrypt geo data","GPS tracking"],a:1,x:"Triggers policies or restricts access based on device/user location.",d:2},{q:"Kubernetes security focuses on:",o:["VM escape","RBAC, network policies, pod security, image scanning","Firewall rules","Antivirus"],a:1,x:"K8s security: RBAC, network policies, pod security standards, image scanning.",d:2}]},
]},
  {
  id:4, title:"Security Operations", weight:28, icon:"⚙️", color:"#2ed573",
  objectives:[
  {id:"4.1",title:"Apply common security techniques to computing resources",
   topics:[
    {id:"4.1.1",title:"Secure Baselines",
     plain:"A secure baseline is a standardized security configuration applied to every system of the same type. CIS Benchmarks are the most widely used source with Level 1 for basic security and Level 2 for high-security environments. DISA STIGs are the military equivalent. Golden images are pre-configured templates you clone to every new machine ensuring identical starting configs. The challenge is drift detection: over time systems change from their baseline through admin modifications and software installs. SCAP scanners continuously check systems against the baseline and alert on unauthorized deviations. Without drift detection your baseline degrades over time.",
     examTip:"Baseline drift: investigate unauthorized change, dont update baseline to match. CIS Benchmarks and DISA STIGs are the two sources to know.",
     tech:"Secure baseline: Standardized security config applied to all systems of a type. Sources: CIS Benchmarks (Level 1/Level 2), DISA STIGs (DoD), vendor guides. Deployment: GPO (Windows), Ansible/Puppet/Chef (IaC), golden images (pre-configured templates). Continuous monitoring: drift detection alerts when systems deviate. Tools: SCAP scanners, Chef InSpec, compliance dashboards.",
     terms:["Secure baseline","CIS Benchmarks","DISA STIGs","Golden image","GPO","Drift detection","SCAP"],
     tasks:["Download CIS Benchmark for your OS and audit 10 settings","Create a golden image VM","Set up drift detection with SCAP"]},
    {id:"4.1.2",title:"Hardening Targets",
     plain:"Hardening means removing everything unnecessary from a system - like stripping a race car of its radio and back seats. Every extra service running, every unused port open, every default account active is a potential door for attackers. Server hardening: disable GUI, remove unnecessary services, close unused ports. Workstation: endpoint protection, application allow-listing, disable autorun. Network devices: change default credentials immediately, disable unused interfaces, enable encrypted management. Mobile: MDM policies, disable developer mode. IoT: network isolation because they often cannot be patched. The CIS Benchmarks provide step-by-step hardening guides for every major OS and application.",
     examTip:"When exam says harden, think REMOVE and DISABLE. Adding monitoring=detective not hardening. Hardening=reducing attack surface.",
     tech:"By target: Mobile (MDM, remote wipe, encryption, screen lock), Workstations (disable services, host firewall, EDR, BitLocker, app allow-listing, disable autorun/USB), Servers (minimal install, no GUI, SSH key-only, remove defaults, disable unused ports), Network devices (change ALL default credentials, disable unused ports, SSH not Telnet, SNMPv3, ACLs), IoT/Embedded (change defaults, separate VLAN, firmware updates, monitor traffic), SCADA/ICS (air gap/segmentation, no internet, vendor-specific, safety-first), Cloud (CIS cloud benchmarks, least privilege IAM, enable logging, encrypt storage).",
     terms:["Hardening","Minimal installation","Disable defaults","Host firewall","EDR","Application allow-listing"],
     tasks:["Harden a Linux server following CIS Level 1","Create hardening checklist per system type","Compare default vs hardened Windows configs"]},
    {id:"4.1.3",title:"Securing Wireless and Mobile",
     plain:"Managing thousands of employee phones is a nightmare without MDM (Mobile Device Management) — it's like a remote control for company phones. Site surveys map WiFi coverage like a floor plan. BYOD = employees use personal devices (cheap but risky). COPE = company owns, personal use allowed (more control).",
     examTip:"BYOD=least control. COPE=most control (company owned). CYOD=choose from approved. Site surveys=WiFi heat maps.",
     tech:"MDM/UEM (Unified Endpoint Management): Remote wipe, enforce encryption/PIN, app management (allow/block), GPS tracking, containerization (separate work/personal data), compliance checking, certificate deployment. Deployment models: BYOD (Bring Your Own Device — least cost, least control, privacy concerns), COPE (Corporate-Owned Personally Enabled — company owns, personal use permitted, more control), CYOD (Choose Your Own Device — employee selects from approved list, company purchases), Corporate-owned (most control, most cost). Site surveys: Assess wireless coverage, interference, AP placement. Heat maps show signal strength. Determines optimal AP count/placement. Wireless security: Disable WPS (brute-forceable), MAC filtering (weak — easily spoofed), reduce signal leakage (power adjustment), guest network isolation.",
     terms:["MDM","UEM","BYOD","COPE","CYOD","Site survey","Heat map","Containerization","Remote wipe","Guest network"],
     tasks:["Perform a wireless site survey using a WiFi analyzer app","Compare BYOD/COPE/CYOD policies in detail","Research MDM solutions and their security features"]},
    {id:"4.1.4",title:"Wireless Security Settings",
     plain:"WPA3 is the latest WiFi security standard — it uses SAE (Simultaneous Authentication of Equals) which means even if an attacker captures your connection, they can't crack it offline. EAP-TLS is the strongest enterprise WiFi auth because both the server AND client must show certificates, like both sides of a meeting showing ID.",
     examTip:"WPA3 SAE prevents offline dictionary attacks. EAP-TLS=mutual certs=strongest. PEAP=server cert+password=most common enterprise.",
     tech:"Evolution: WEP (broken, never use) → WPA (TKIP, deprecated) → WPA2 (AES-CCMP, current minimum) → WPA3 (SAE/Dragonfly handshake, forward secrecy, protected management frames). WPA3-Personal: SAE replaces PSK — resistant to offline dictionary attacks, provides forward secrecy. WPA3-Enterprise: 192-bit security suite, CNSA (Commercial National Security Algorithm). Enterprise authentication (802.1X + RADIUS): EAP-TLS (mutual certificate authentication — strongest, requires client certs, PKI infrastructure), PEAP (server cert only, tunnels MSCHAPv2 inside TLS — most common enterprise), EAP-TTLS (similar to PEAP, more flexible inner methods), EAP-FAST (Cisco, uses PAC instead of certificates). 802.1X flow: Supplicant (client) → Authenticator (AP/switch) → Authentication server (RADIUS). Wireless IDS/IPS (WIDS/WIPS): Detect rogue APs, deauth attacks, evil twins.",
     terms:["WPA3","SAE","WPA2","AES-CCMP","802.1X","RADIUS","EAP-TLS","PEAP","EAP-FAST","WIDS","Supplicant","Authenticator"],
     tasks:["Configure WPA3-Enterprise with RADIUS on a lab AP","Compare all EAP types in a detailed table","Explain the 802.1X authentication flow step by step"]},
    {id:"4.1.5",title:"Application Security",
     plain:"Secure coding = building a house with proper foundations instead of patching cracks later. Input validation = checking every delivery at the door so nobody sneaks in contraband. Code signing = sealing software with your signature so users know it wasn't tampered with. Sandboxing = testing suspicious things in a sealed room.",
     examTip:"Allow-list preferred over deny-list. Server-side mandatory. HttpOnly(no JS), Secure(HTTPS), SameSite(CSRF). Code signing=publisher identity.",
     tech:"Input validation: Whitelist/allow-list preferred (only accept known-good), reject/sanitize all unexpected input. Prevents injection attacks. Server-side validation mandatory (client-side can be bypassed). Secure cookies: HttpOnly (prevents JavaScript access — XSS protection), Secure flag (HTTPS only), SameSite (CSRF protection). Code signing: Digital signature on executables/scripts verifies publisher identity and code integrity. Certificates from trusted CA. Sandboxing: Isolated execution environment for untrusted code. Browser sandboxes, application sandboxes, malware analysis sandboxes. Memory management: Buffer overflow prevention (bounds checking, ASLR, DEP). Safe functions (strncpy vs strcpy). SDLC security: Security integrated into development lifecycle — threat modeling, secure coding standards, code review, SAST/DAST, penetration testing before release.",
     terms:["Input validation","Secure cookies","HttpOnly","Code signing","Sandboxing","SDLC","Threat modeling","SAST","DAST"],
     tasks:["Review OWASP Secure Coding Practices Quick Reference","Implement input validation for a simple web form","Research how browser sandboxing protects against malicious websites"]},
   ],
   questions:[
    {q:"Strongest wireless EAP type requiring both client AND server certificates:",o:["EAP-MD5","PEAP","EAP-TLS","EAP-FAST"],a:2,x:"EAP-TLS = mutual certificate authentication, strongest EAP method.",d:2},
    {q:"Employees select from 5 approved company-purchased phones:",o:["BYOD","COPE","CYOD","Corporate-owned"],a:2,x:"CYOD = Choose Your Own Device from approved list, company purchases.",d:2},
    {q:"Automated detection of configuration changes from approved standard:",o:["Vulnerability scan","Baseline drift detection","Penetration test","Patch management"],a:1,x:"Drift detection monitors and alerts on deviations from secure baseline.",d:2},
    {q:"Cookie flag preventing JavaScript from accessing the cookie:",o:["Secure","SameSite","HttpOnly","Signed"],a:2,x:"HttpOnly flag prevents client-side JavaScript from accessing the cookie, mitigating XSS.",d:2},
    {q:"WPA3-Personal improves on WPA2-Personal primarily through:",o:["Longer passwords","SAE handshake preventing offline attacks","Certificate authentication","Faster speeds"],a:1,x:"SAE (Simultaneous Authentication of Equals) replaces PSK, preventing offline dictionary attacks.",d:2},
   ]},
  {id:"4.2",title:"Explain the security implications of proper hardware, software, and data asset management",
   topics:[
    {id:"4.2.1",title:"Asset Management",
     plain:"You cannot protect what you dont know exists. Asset management tracks every device and application from acquisition through secure destruction. Lifecycle: Procurement (verify vendor) then Deployment (baseline config, add to inventory, assign owner) then Operation (patch, monitor) then Decommission (sanitize per NIST SP 800-88). Three sanitization levels: Clear (overwrite, reuse within org), Purge (crypto erase/degauss, reuse externally), Destroy (shred/incinerate). Every asset needs a designated owner responsible for classification and protection. EOL means no new development. EOSL means no security patches and is an urgent risk requiring migration planning.",
     examTip:"NIST 800-88: Clear < Purge < Destroy. EOL!=EOSL. EOSL=no patches=urgent. Decommission scenario=which sanitization method.",
     tech:"Asset lifecycle: Procurement (vendor security assessment, supply chain verification) → Deployment (baseline config, asset tag, inventory entry, account provisioning) → Operation (patching, monitoring, compliance) → Maintenance (upgrades, refreshes) → Decommission (data sanitization per NIST SP 800-88, account deactivation, inventory removal, physical destruction/recycling). NIST SP 800-88 sanitization: Clear (logical overwrite, for reuse within org), Purge (makes recovery infeasible — cryptographic erase, degaussing, for reuse outside org), Destroy (physical destruction — shredding, incineration, for highest sensitivity). Asset inventory: Hardware, software, data, cloud resources. CMDB tracks relationships. Discovery scans find unknown assets. Ownership: Every asset needs an owner responsible for classification, protection, access decisions. EOL/EOSL: End of Life (no more sales/development), End of Service Life (no more security patches — critical risk, must migrate or implement compensating controls).",
     terms:["Asset lifecycle","NIST SP 800-88","Clear","Purge","Destroy","CMDB","Asset inventory","EOL","EOSL","Data sanitization"],
     tasks:["Create asset inventory of your home network","Research NIST SP 800-88 Clear/Purge/Destroy guidelines","Design a decommission checklist with proper data sanitization"]},
   ],
   questions:[
    {q:"Before disposing of a server that contained PHI, the FIRST step is:",o:["Physically destroy the drives","Sanitize per NIST SP 800-88","Remove drives and store them","Format the drives"],a:1,x:"NIST SP 800-88 provides the standard for proper media sanitization based on data sensitivity and media type.",d:2},
    {q:"Software no longer receiving security patches from the vendor is:",o:["EOL","EOSL","Deprecated","Legacy"],a:1,x:"EOSL = End of Service Life means no more security updates — critical security risk.",d:1},
   ]},
  {id:"4.3",title:"Explain various activities associated with vulnerability management",
   topics:[
    {id:"4.3.1",title:"Vulnerability Scanning",
     plain:"A vulnerability scanner is like a home inspector checking for broken locks, faulty wiring, and structural problems. Credentialed scan = the inspector has keys to every room (finds more). Non-credentialed = inspector can only check what's visible from outside (faster but misses things).",
     examTip:"Credentialed=deep accurate fewer false positives. Non-credentialed=attacker view more false positives. Agent-based=continuous.",
     tech:"Scan types: Credentialed/authenticated (admin credentials — deeper, more accurate, fewer false positives, identifies installed software/patches/configs), Non-credentialed/unauthenticated (external perspective, no login — simulates attacker view, more false positives), Agent-based (software on each host reports continuously — doesn't need network credentials). Active vs Passive: Active (sends probes — comprehensive but detectable), Passive (monitors traffic — less invasive but limited). Tools: Nessus, Qualys, OpenVAS/GVM, Rapid7 InsightVM. Scan scheduling: Regular intervals, after changes, before audits. Scope: internal networks, external perimeter, cloud assets, web applications, databases.",
     terms:["Credentialed scan","Non-credentialed","Agent-based","Active scanning","Passive scanning","Nessus","Qualys","OpenVAS"],
     tasks:["Run OpenVAS against Metasploitable VM and analyze results","Compare credentialed vs non-credentialed scan results on same target","Create a vulnerability scanning schedule and scope document"]},
    {id:"4.3.2",title:"Threat Intelligence",
     plain:"Threat intelligence is knowing what the bad guys are planning before they attack. STIX is the language used to describe threats (like a police report format). TAXII is how those reports get shared between organizations (like the secure postal system for police reports). CVE is a unique ID for each known vulnerability.",
     examTip:"CVE=ID. CVSS=score 0-10. NVD=NIST database. STIX=format. TAXII=transport. ISACs=industry sharing.",
     tech:"Threat intelligence sources: OSINT (open-source — social media, news, public databases), Commercial feeds (Recorded Future, Mandiant, CrowdStrike), Government (CISA, US-CERT, NIST NVD), ISACs (Information Sharing and Analysis Centers — industry-specific), Dark web monitoring. Vulnerability identification: CVE (Common Vulnerabilities and Exposures — unique identifier, e.g., CVE-2021-44228 = Log4Shell), CVSS (Common Vulnerability Scoring System — 0-10 severity: None 0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0, Base/Temporal/Environmental scores), NVD (National Vulnerability Database — NIST-maintained, enriches CVEs with CVSS scores). Sharing: STIX (Structured Threat Information eXpression — JSON format for threat data), TAXII (Trusted Automated eXchange of Intelligence Information — transport protocol for STIX data). Threat feeds: Automated IoC feeds integrated into SIEM/IPS for real-time blocking.",
     terms:["STIX","TAXII","CVE","CVSS","NVD","OSINT","ISAC","Threat feed","IoC","CISA"],
     tasks:["Look up 5 recent CVEs and explain their CVSS scores","Research STIX/TAXII and how organizations share threat intelligence","Subscribe to a threat intel feed and integrate with a SIEM"]},
    {id:"4.3.3",title:"Penetration Testing",
     plain:"A penetration test is hiring a professional burglar to break into your house and write a report about how they did it. Unknown/black box = they know nothing about your house. Known/white box = they have the blueprints. Partially known/gray box = they have some info like an employee would.",
     examTip:"Black box=no knowledge. White box=full access. Gray=partial. Always WRITTEN AUTHORIZATION. Without it its just hacking.",
     tech:"Perspectives: Unknown environment (black box — no prior knowledge, simulates external attacker), Known environment (white box — full access to source code, architecture, credentials, most thorough), Partially known (gray box — some info like authenticated user, most realistic for insider threat simulation). Phases: Reconnaissance (passive OSINT + active scanning) → Scanning/enumeration → Vulnerability analysis → Exploitation → Post-exploitation (lateral movement, persistence, data exfiltration) → Reporting. Rules of engagement (ROE): Scope (in-scope/out-of-scope systems), timeline, authorized techniques, emergency contacts, legal authorization, reporting requirements. Bug bounty: Organization invites external researchers to find vulnerabilities for rewards. Platforms: HackerOne, Bugcrowd. Responsible disclosure: Researcher→vendor→patch→public disclosure.",
     terms:["Penetration test","Black box","White box","Gray box","Rules of engagement","Reconnaissance","Exploitation","Bug bounty"],
     tasks:["Complete beginner penetration testing labs on TryHackMe","Write a Rules of Engagement template","Research bug bounty program structures and payouts"]},
    {id:"4.3.4",title:"Vulnerability Remediation and Reporting",
     plain:"Finding vulnerabilities means nothing if you don't fix them. Prioritization: a critical vulnerability on an internet-facing server gets fixed first, a low-severity issue on an internal test box can wait. Exceptions need documented approval. Reporting tracks what was found, what was fixed, and what's still open.",
     examTip:"Prioritize: CVSS+asset value+exploitability. Always validate fix with re-scan. Remediation: patch > compensating > accept.",
     tech:"Prioritization: CVSS score + asset value + exploitability + business context = true risk. A CVSS 7.0 on DMZ web server > CVSS 9.0 on isolated test box. Remediation options: Patch (preferred — apply vendor fix), Compensating control (WAF rule, segmentation when patch unavailable), Configuration change (disable vulnerable feature), Accept risk (documented decision by risk owner, temporary with review date). SLA by severity: Critical (24-48hrs), High (7 days), Medium (30 days), Low (90 days). Exceptions: Documented acceptance with business justification, risk owner approval, review date, compensating controls. Validation: Re-scan after remediation to confirm fix. Reporting: Executive summary (risk overview, trends, compliance status), Technical details (per-vulnerability: description, affected systems, CVSS, remediation steps, evidence), Metrics (mean time to remediate, vulnerability density, aging report).",
     terms:["CVSS prioritization","Remediation SLA","Compensating control","Risk acceptance","Validation scan","Exception process","Vulnerability aging"],
     tasks:["Create a vulnerability remediation prioritization matrix","Design a vulnerability management report template","Calculate mean time to remediate from sample vulnerability data"]},
   ],
   questions:[
    {q:"Scan using admin credentials to check installed software and missing patches:",o:["Non-credentialed","Credentialed","Penetration test","Fuzzing"],a:1,x:"Credentialed scans use admin creds for deeper, more accurate results.",d:1},
    {q:"CVSS score of 9.2 is classified as:",o:["Medium","High","Critical","Severe"],a:2,x:"CVSS Critical = 9.0-10.0. High = 7.0-8.9. Medium = 4.0-6.9.",d:1},
    {q:"Format used to share structured threat intelligence data:",o:["CVE","CVSS","STIX","NVD"],a:2,x:"STIX = Structured Threat Information eXpression, the standard format for sharing threat data.",d:2},
   ]},
  {id:"4.4",title:"Explain security alerting and monitoring concepts and tools",
   topics:[
    {id:"4.4.1",title:"Monitoring and Log Management",
     plain:"SIEM is the security command center receiving ALL camera/sensor/alarm feeds. Each feed alone is noise. SIEM correlates: back door opened at 3AM + server room motion + admin login from Russia = ALERT. Without NTP time synchronization, you can't correlate events because timestamps don't match.",
     examTip:"SIEM collects+correlates+alerts. NTP sync critical for log correlation. Without synchronized time cant reconstruct timelines.",
     tech:"Log sources: Firewall (allowed/denied traffic), IDS/IPS (alerts), OS (authentication, privilege use, system events), Application (errors, access, transactions), DNS (query logs), DHCP (lease assignments), Proxy (web access), Email gateway. SIEM functions: Collection → Aggregation → Normalization (common format) → Indexing → Correlation (rules linking events across sources) → Alerting → Dashboards → Retention/archiving. Syslog: Standard logging protocol — UDP 514 (unreliable), TCP 514 (reliable), TLS 6514 (encrypted). Severity levels 0-7 (Emergency to Debug). NTP (Network Time Protocol): Synchronize all system clocks. Critical for log correlation — events must have accurate timestamps to reconstruct incident timelines. Stratum hierarchy. Log integrity: Hashing logs, write-once storage, centralized collection (prevents local tampering).",
     terms:["SIEM","Log correlation","Normalization","Syslog","NTP","Log retention","Log integrity","Aggregation"],
     tasks:["Set up ELK Stack or Wazuh SIEM and ingest Windows event logs","Write 3 SIEM correlation rules for detecting attacks","Configure centralized syslog collection with TLS encryption"]},
    {id:"4.4.2",title:"Security Alerting and SOAR",
     plain:"SOAR is the autopilot for security — when SIEM detects a phishing email, SOAR automatically quarantines the email, blocks the sender, checks if anyone clicked the link, and isolates any compromised machine. No human needed for routine responses. Humans handle the complex stuff.",
     examTip:"SOAR automates via playbooks. Threat hunting=proactive hypothesis-driven. MTTD=time to detect. MTTR=time to respond.",
     tech:"Alert management: Tuning (reduce false positives — adjust thresholds, whitelist known-good), Prioritization (severity + asset value + threat intel context), Escalation procedures, Alert fatigue mitigation. SOAR (Security Orchestration, Automation, and Response): Automated playbooks/runbooks for common incidents. Examples: Auto-block IP after X failed logins, auto-quarantine phishing emails, auto-isolate endpoint after malware detection, auto-enrich alerts with threat intel. Metrics: MTTD (Mean Time to Detect — time from incident to discovery), MTTR (Mean Time to Respond — time from detection to containment/resolution). Threat hunting: Proactive search for threats that evade automated detection. Hypothesis-driven, uses IoCs and behavioral analytics. NetFlow analysis: Network traffic metadata (source/dest IP, ports, bytes, duration) without full packet capture. Identifies anomalous patterns.",
     terms:["SOAR","Playbook","Runbook","MTTD","MTTR","Alert fatigue","Threat hunting","NetFlow","Alert tuning"],
     tasks:["Create 3 SOAR playbooks for common incident types","Calculate MTTD and MTTR from sample incident data","Explain the difference between reactive monitoring and proactive threat hunting"]},
    {id:"4.4.3",title:"Security Tools",
     plain:"A vulnerability scanner checks for weaknesses. A packet analyzer (Wireshark) reads network traffic like opening and reading every envelope going through the post office. A protocol analyzer decodes the language being spoken. SCAP automates compliance checking against benchmarks.",
     examTip:"Nmap=ports. Wireshark=packets. Nessus=vulns. SCAP=compliance. Metasploit=exploitation. Hashcat=passwords.",
     tech:"Vulnerability scanners: Nessus, Qualys, OpenVAS/GVM, Rapid7. Protocol analyzers: Wireshark (packet capture and deep analysis), tcpdump (CLI capture). Network scanners: Nmap (port scanning, OS detection, service enumeration, scripting engine). SCAP (Security Content Automation Protocol): Automated compliance checking using OVAL (vulnerability definitions), XCCDF (benchmark checklists), CPE (platform identification), CVE (vulnerability naming). Benchmarking tools: CIS-CAT (automated CIS Benchmark scanning). Password tools: For auditing — John the Ripper, Hashcat (verify password policy compliance). Forensic tools: FTK Imager, Autopsy, EnCase, Volatility (memory analysis). Exploitation frameworks: Metasploit (for authorized pentesting only).",
     terms:["Wireshark","Nmap","SCAP","Nessus","Metasploit","FTK Imager","Hashcat","tcpdump","OVAL","XCCDF"],
     tasks:["Perform Nmap scan of lab network and interpret results","Capture and analyze packets with Wireshark","Run a SCAP compliance scan against CIS Benchmark"]},
   ],
   questions:[
    {q:"All log sources need synchronized time for correlation. Protocol:",o:["SNMP","NTP","Syslog","LDAP"],a:1,x:"NTP synchronizes clocks across all systems — critical for accurate log correlation.",d:1},
    {q:"System that auto-blocks malicious IP across all firewalls after SIEM alert:",o:["IDS","SIEM","SOAR","EDR"],a:2,x:"SOAR executes automated playbooks in response to SIEM alerts.",d:2},
    {q:"Proactive searching for threats that evade automated detection:",o:["Vulnerability scanning","Penetration testing","Threat hunting","Log review"],a:2,x:"Threat hunting is proactive, hypothesis-driven searching beyond automated detection.",d:2},
   ]},
  {id:"4.5",title:"Modify enterprise capabilities to enhance security",
   topics:[
    {id:"4.5.1",title:"Email Security",
     plain:"SPF+DKIM+DMARC is the email authentication trio. SPF = a list of authorized mail servers for your domain. DKIM = a digital signature proving the email wasn't tampered with in transit. DMARC = the policy saying what to do if SPF or DKIM fails (reject, quarantine, or accept).",
     examTip:"SPF=authorized servers. DKIM=crypto signature. DMARC=policy (none/quarantine/reject). S/MIME=end-to-end encryption.",
     tech:"SPF (Sender Policy Framework): DNS TXT record listing authorized sending servers (v=spf1 include:... -all). Receiving server checks if sending IP is authorized. DKIM (DomainKeys Identified Mail): Cryptographic signature added to email headers. Sending server signs with private key, receiving server verifies with public key in DNS. Proves integrity and authenticity. DMARC (Domain-based Message Authentication, Reporting & Conformance): Policy record specifying how to handle emails failing SPF/DKIM (p=none/quarantine/reject). Also provides reporting. S/MIME: End-to-end email encryption and digital signatures using certificates. Email gateway security: Anti-spam, anti-malware, URL rewriting/sandboxing, attachment sandboxing, impersonation protection.",
     terms:["SPF","DKIM","DMARC","S/MIME","Email gateway","Anti-spam","URL rewriting"],
     tasks:["Check SPF/DKIM/DMARC records for 5 domains using MXToolbox","Configure SPF and DMARC for a test domain","Explain the S/MIME certificate-based email encryption process"]},
    {id:"4.5.2",title:"Endpoint Security and DLP",
     plain:"EDR is a detective inside every computer watching behavior — not just checking IDs at the door (antivirus) but monitoring what programs DO once inside. XDR extends this across the whole building — network, cloud, email, endpoints all connected. DLP on endpoints prevents sensitive data from leaving via USB, email, or printing.",
     examTip:"AV=signatures. EDR=behavioral+response. XDR=EDR across all domains. FIM=file change detection.",
     tech:"Antivirus/anti-malware: Signature-based (known patterns — fast, accurate, can't detect unknown), Heuristic (analyze behavior patterns — catches variants), Behavioral (monitor runtime behavior — catches zero-days, higher false positives). EDR (Endpoint Detection and Response): Continuous monitoring, behavioral analysis, automated containment (isolate endpoint), forensic data collection, threat hunting support. Goes beyond AV by detecting fileless attacks, lateral movement. XDR (Extended Detection and Response): Correlates data across endpoints, network, cloud, email, identity — unified detection and response. Reduces silos. DLP: Endpoint agent monitors data movement — block USB copy of classified files, prevent screenshot of PII, control printing, monitor clipboard. Host-based firewall: Windows Defender Firewall, iptables/nftables (Linux). FIM (File Integrity Monitoring): Detect unauthorized changes to critical files — Tripwire, OSSEC. HIDS/HIPS: Host-based IDS/IPS — monitor system calls, file changes, registry modifications.",
     terms:["EDR","XDR","Antivirus","Heuristic","Behavioral analysis","DLP","FIM","HIDS","HIPS","Host firewall"],
     tasks:["Compare 3 EDR solutions and their detection capabilities","Configure Windows Defender Firewall with advanced rules","Set up OSSEC for file integrity monitoring on a test server"]},
    {id:"4.5.3",title:"Secure Protocols",
     plain:"Every insecure protocol has a secure replacement - think of upgrading from postcards to sealed envelopes. Telnet sends passwords in plaintext, SSH encrypts everything. FTP is unencrypted file transfer, SFTP wraps it in SSH. HTTP is the unencrypted web, HTTPS adds TLS. SNMP v1/v2c sends community strings in cleartext, SNMPv3 adds authentication and encryption. The exam loves port matching: know that SSH=22, HTTPS=443, LDAPS=636, IMAPS=993, SMTPS=587, SNMPv3=161, Syslog TLS=6514. The rule is simple: if a protocol doesnt have encryption built in, it shouldnt be used in production.",
     examTip:"Memorize secure replacements: Telnet to SSH(22), HTTP to HTTPS(443), FTP to SFTP(22), LDAP to LDAPS(636), IMAP to IMAPS(993), SMTP to SMTPS(587).",
     tech:"Protocol mapping (insecure → secure): Telnet(23) → SSH(22), FTP(21) → SFTP(22)/FTPS(990), HTTP(80) → HTTPS(443), SNMP v1/v2c → SNMPv3 (authentication + encryption), LDAP(389) → LDAPS(636), IMAP(143) → IMAPS(993), POP3(110) → POP3S(995), SMTP(25) → SMTPS(587 with STARTTLS), DNS(53) → DoH(443)/DoT(853), NTP → NTS (Network Time Security). TLS 1.3: Current standard, mandatory ECDHE, removed weak ciphers, 0-RTT resumption, faster handshake. SSH: Key-based authentication preferred over passwords. Port 22. SCP/SFTP for file transfer. Disable SSH v1. IPSec: Network layer encryption — tunnel mode (VPN) or transport mode (host-to-host).",
     terms:["SSH","SFTP","HTTPS","TLS 1.3","SNMPv3","LDAPS","IMAPS","SMTPS","DoH","DoT","NTS","IPSec"],
     tasks:["Create a complete insecure→secure protocol mapping table with ports","Verify TLS version and cipher suite of 5 websites","Configure SSH key-based authentication and disable password login"]},
   ],
   questions:[
    {q:"Three DNS records forming the email authentication trio:",o:["A/AAAA/MX","SPF/DKIM/DMARC","PTR/SRV/TXT","CNAME/NS/SOA"],a:1,x:"SPF+DKIM+DMARC work together for complete email authentication.",d:1},
    {q:"EDR differs from traditional antivirus primarily by:",o:["Using signatures","Continuous behavioral monitoring and response","Faster scanning","Lower resource usage"],a:1,x:"EDR provides continuous behavioral monitoring, automated response, and forensic capabilities beyond signature matching.",d:2},
    {q:"Secure replacement for LDAP:",o:["LDAPS (port 636)","SNMP","TFTP","RADIUS"],a:0,x:"LDAPS adds TLS encryption to LDAP on port 636.",d:1},
   ]},
  {id:"4.6",title:"Given a scenario, implement and maintain identity and access management",
   topics:[
    {id:"4.6.1",title:"Identity and Access Management (IAM)",
     plain:"IAM controls who gets in, what they can access, and logs everything they do. Provisioning creates access on day one. Deprovisioning removes ALL access same-day when someone leaves - delayed deprovisioning is a major audit finding. SSO means one login opens all apps. Federation extends trust across organizations using standards like SAML (enterprise SSO), OAuth (API authorization), and OIDC (authentication layer on OAuth). The key distinction: SAML carries authentication assertions, OAuth issues access tokens for authorization only, and OIDC adds identity/authentication on top of OAuth. Directory services (Active Directory, LDAP) are the central databases storing user identities and group memberships.",
     examTip:"SAML=enterprise SSO. OAuth=authorization only (NOT authentication). OIDC=authentication+OAuth. CompTIA WILL trick you on OAuth vs OIDC.",
     tech:"IAM lifecycle: Provisioning (create accounts, assign roles/groups, initial permissions based on job function) → Review (periodic access reviews — quarterly/annually, recertification) → Modify (role changes, project assignments) → Deprovision (disable accounts on termination — same-day for involuntary, coordinated for voluntary). SSO (Single Sign-On): One authentication grants access to multiple applications. Reduces password fatigue, centralizes authentication. SAML 2.0: XML-based, enterprise SSO. IdP (Identity Provider) authenticates user, sends assertion to SP (Service Provider). Browser redirect-based. OAuth 2.0: Authorization framework for APIs. Issues access tokens. Used for third-party app access ('Login with Google'). NOT authentication. OpenID Connect (OIDC): Authentication layer on top of OAuth 2.0. Returns ID token with user identity. Federation: Trust relationship between organizations. Users authenticated by home org are trusted by partner orgs.",
     terms:["IAM","Provisioning","Deprovisioning","SSO","SAML","OAuth","OIDC","Federation","IdP","SP","Access token","Assertion"],
     tasks:["Set up Keycloak with SAML-based SSO for a test app","Compare SAML vs OAuth vs OIDC with specific use cases","Design an employee onboarding/offboarding IAM checklist"]},
    {id:"4.6.2",title:"Access Controls and Permissions",
     plain:"RBAC = hospital badge system: your role (doctor/nurse/janitor) determines which doors open. MAC = military clearance: you need TOP SECRET clearance AND need-to-know to access. DAC = you own the file and decide who else can see it. ABAC = the smart system that checks your role + time + location + device before granting access.",
     examTip:"DAC=owner sets (common, least secure). MAC=system labels (most restrictive). RBAC=role-based (enterprise). ABAC=attributes (most granular).",
     tech:"DAC (Discretionary Access Control): Resource owner sets permissions. Most common (Windows NTFS, Linux file permissions). Flexible but less secure — users may grant excessive access. MAC (Mandatory Access Control): System-enforced labels/clearances. Data has classification label (Confidential/Secret/Top Secret), users have clearance level. User CANNOT change permissions. SELinux, AppArmor. Most restrictive. RBAC (Role-Based Access Control): Permissions assigned to roles, users assigned to roles. Most commonly implemented in enterprises. Simplifies management — change role, permissions follow. ABAC (Attribute-Based Access Control): Dynamic — evaluates multiple attributes per request: user role + department + time + location + device health + data sensitivity. Most granular and flexible. Rule-based: If-then logic (if time > 6PM then deny, if source IP = external then require MFA). Principle of least privilege: Minimum necessary access. Just-In-Time (JIT): Access granted only when needed, automatically revoked after time period.",
     terms:["DAC","MAC","RBAC","ABAC","Rule-based","Least privilege","JIT","SELinux","AppArmor","Need-to-know"],
     tasks:["Design an RBAC model for a 100-person company with 5 departments","Compare DAC/MAC/RBAC/ABAC with scenarios for each","Configure SELinux and demonstrate mandatory access control"]},
    {id:"4.6.3",title:"Multifactor Authentication",
     plain:"MFA requires proof from two or more DIFFERENT categories. The five categories: something you KNOW (password, PIN), something you HAVE (phone, token, smart card), something you ARE (fingerprint, face, retina), somewhere you ARE (GPS, IP), something you DO (typing pattern). Critical rule: factors must be from DIFFERENT categories. Password plus PIN is NOT MFA because both are knowledge. Password plus fingerprint IS MFA. SMS codes are the weakest possession factor because SIM swapping can steal your number. FIDO2/WebAuthn is phishing-resistant because the security key is cryptographically bound to the legitimate websites domain - a phishing site cannot intercept it.",
     examTip:"Two knowledge factors is NOT MFA. SMS discouraged by NIST (SIM swapping). FIDO2=phishing-resistant=strongest. Biometrics: FAR, FRR, CER.",
     tech:"Factors: Something you know (password, PIN, security question), Something you have (smart card, hardware token/FIDO2 key, authenticator app, phone), Something you are (fingerprint, facial recognition, retina/iris scan, voice), Somewhere you are (GPS, IP geolocation), Something you do (typing pattern, gait, signature dynamics). MFA requires 2+ DIFFERENT categories. Two passwords = NOT MFA. Implementation: TOTP (Time-based One-Time Password — Google Authenticator, 30-second codes), Push notification (Duo, Microsoft Authenticator — approve/deny), FIDO2/WebAuthn (passwordless — hardware security key or biometric, phishing-resistant, NIST recommended), SMS codes (weakest — vulnerable to SIM swapping, SS7 attacks, NIST discourages). Passwordless: FIDO2 eliminates passwords entirely — biometric or security key authenticates directly.",
     terms:["MFA","TOTP","FIDO2","WebAuthn","Push notification","SIM swapping","Passwordless","Biometrics","Hardware token"],
     tasks:["Set up TOTP authenticator for 5 accounts","Research FIDO2/WebAuthn and how it prevents phishing","Compare MFA methods by security strength and user experience"]},
    {id:"4.6.4",title:"Password Security Concepts",
     plain:"Password length beats complexity every time. 'correct horse battery staple' (25 chars) is harder to crack than 'P@ssw0rd!' (9 chars). Password managers create and store unique passwords for everything. Password vaulting for admins stores privileged credentials securely with checkout/checkin.",
     examTip:"NIST: length over complexity, no forced rotation unless compromised, check breached lists, support MFA.",
     tech:"Password policies: Length (minimum 12-16+, NIST SP 800-63B recommends length over complexity), Complexity (uppercase + lowercase + numbers + symbols — being de-emphasized by NIST), Expiration (NIST now recommends NO forced rotation unless compromise suspected — rotation leads to weak patterns like Season2024!), History (prevent reuse of last N passwords), Lockout (threshold + duration + reset). Password managers: Generate and store unique, complex passwords. Browser-based or dedicated (1Password, Bitwarden, KeePass). Password vaulting/PAM: Privileged Access Management — vault stores admin credentials, checkout/checkin system, session recording, JIT access, automatic password rotation. NIST SP 800-63B guidance: Favor length, allow all characters including spaces, no arbitrary complexity rules, no periodic rotation, check against breached password lists (Have I Been Pwned), implement MFA.",
     terms:["Password policy","NIST SP 800-63B","Password manager","PAM","Password vault","Account lockout","Password history","Breached password list"],
     tasks:["Review NIST SP 800-63B password guidelines","Set up a password manager and migrate 10 accounts","Research PAM solutions and their features"]},
    {id:"4.6.5",title:"Privileged Access Management",
     plain:"Admin accounts are the master keys — if compromised, the attacker owns everything. PAM locks these master keys in a vault. Admins must check out the key, their session is recorded, and the key is returned and changed afterward. JIT means admin access is only granted for the exact time needed.",
     examTip:"PAM vaults credentials, records sessions, JIT access, auto-rotates passwords. Service accounts=high risk, overprivileged, rarely changed.",
     tech:"PAM components: Credential vault (encrypted storage of privileged passwords/keys/certificates), Session management (recording, monitoring, real-time termination of admin sessions), JIT access (temporary elevation — request, approve, time-limited, auto-revoke), Privileged account discovery (find all admin/service accounts including unknown ones), Password rotation (automatic rotation after each use or on schedule), Least privilege enforcement (no permanent admin rights), MFA for privileged access. Service accounts: Non-interactive accounts used by applications/services. Risks: often have excessive privileges, passwords rarely rotated, shared among admins. PAM manages these. Solutions: CyberArk, BeyondTrust, Delinea (Thycotic/Centrify), HashiCorp Vault.",
     terms:["PAM","Credential vault","JIT access","Session recording","Service account","Privileged account discovery","Auto-rotation"],
     tasks:["Research CyberArk or HashiCorp Vault architecture","Implement sudo with logging as basic PAM","Audit your environment for service accounts with excessive privileges"]},
   ],
   questions:[
    {q:"Access determined by user role + time of day + device health + location:",o:["RBAC","MAC","DAC","ABAC"],a:3,x:"ABAC evaluates multiple attributes dynamically per access request.",d:2},
    {q:"Password + fingerprint = MFA because:",o:["Two knowledge factors","Two inherence factors","Knowledge + inherence (different categories)","Possession + inherence"],a:2,x:"Password=knowledge, fingerprint=inherence. Different factor categories = true MFA.",d:1},
    {q:"SAML 2.0 is primarily used for:",o:["API authorization","Enterprise web SSO","Password hashing","Wireless authentication"],a:1,x:"SAML 2.0 enables SSO via XML assertions between Identity Provider and Service Provider.",d:1},
    {q:"NIST SP 800-63B recommends against:",o:["MFA","Long passwords","Forced periodic password rotation","Password managers"],a:2,x:"NIST discourages mandatory password rotation as it leads to weaker passwords (predictable patterns).",d:2},
   ]},
  {id:"4.7",title:"Explain the importance of automation and orchestration related to secure operations",
   topics:[
    {id:"4.7.1",title:"Incident Response Process",
     plain:"IR is a hospital trauma team: Preparation (training/equipment BEFORE emergencies), Detection (patient arrives — triage and assess severity), Containment (stop the bleeding — isolate the problem), Eradication (surgery — remove the cause), Recovery (rehabilitation — restore normal operations), Lessons Learned (case review — what can we improve?).",
     examTip:"NIST 800-61: Preparation, Detection/Analysis, Containment, Eradication, Recovery, Lessons Learned. Contain=isolate, DONT power off.",
     tech:"NIST SP 800-61 phases: 1) Preparation: IR plan, team roles (IR manager, analysts, forensics, legal, PR, management), communication plan, tools/resources ready, training/tabletop exercises. 2) Detection & Analysis: Monitoring (SIEM alerts, IDS, EDR, user reports), triage, determine scope/severity, evidence preservation, documentation begins. 3) Containment: Short-term (isolate affected systems — network disconnect, disable accounts) and Long-term (implement temporary fixes while permanent solution developed). Do NOT power off systems (preserves volatile evidence). 4) Eradication: Remove malware, patch vulnerabilities, close attack vectors, rebuild compromised systems from clean images. 5) Recovery: Restore from backups, return systems to production, enhanced monitoring for recurrence, phased restoration. 6) Lessons Learned: Post-incident review within 1-2 weeks, document timeline, what worked/didn't, update IR plan, share intelligence.",
     terms:["NIST SP 800-61","Preparation","Detection","Containment","Eradication","Recovery","Lessons learned","IR plan","Triage"],
     tasks:["Create a complete IR plan with roles, contacts, and procedures","Conduct a tabletop exercise for a ransomware scenario","Document an incident timeline from a case study"]},
    {id:"4.7.2",title:"Digital Forensics",
     plain:"Digital forensics = crime scene investigation for computers. Every piece of evidence must be documented, photographed, sealed, and tracked through a chain of custody. If evidence is handled improperly, it's inadmissible in court. Order of volatility = collect the most fragile evidence first (RAM disappears when power is lost).",
     examTip:"Volatility order: registers, RAM, swap, disk, logs, archive. Most volatile first. Chain of custody=every handler. Write blocker=preserve evidence.",
     tech:"Order of volatility (collect first → last): CPU registers/cache → RAM → Swap/temp files → Hard drive → Remote logs → Archival media. Chain of custody: Documented record of WHO handled evidence, WHEN, WHERE, and HOW. Any gap = evidence may be inadmissible. Write blockers: Hardware/software preventing modification of original evidence during acquisition. Critical for forensic integrity. Forensic imaging: Bit-for-bit copy of entire drive (dd, FTK Imager, EnCase). Hash original AND copy (MD5 + SHA-256) — hashes must match to prove copy is exact duplicate. Legal hold: Directive to preserve all relevant electronic data for litigation. Overrides normal retention/deletion policies. Forensic tools: FTK Imager (imaging), Autopsy (analysis — open source), EnCase (commercial), Volatility (memory forensics), Wireshark/tcpdump (network forensics). E-discovery: Process of identifying, collecting, and producing electronically stored information for legal proceedings.",
     terms:["Order of volatility","Chain of custody","Write blocker","Forensic imaging","Legal hold","FTK Imager","Autopsy","Volatility","E-discovery"],
     tasks:["Practice forensic imaging with FTK Imager and verify hash integrity","Create a chain of custody form template","Analyze a memory dump with Volatility framework"]},
    {id:"4.7.3",title:"Automation and Orchestration",
     plain:"Automation = making a single task happen automatically (auto-lock the door at midnight). Orchestration = coordinating multiple automated tasks into a workflow (when intruder detected: lock doors, turn on lights, call police, record cameras — all automatically in sequence).",
     examTip:"Automation=single tasks. Orchestration=coordinates multiple. Guard rails=human approval for high-impact. Always have rollback.",
     tech:"Automation use cases: User provisioning/deprovisioning, patch deployment, vulnerability scanning scheduling, log collection, backup execution, certificate renewal, compliance checks. Orchestration: SOAR platforms coordinate multiple automated actions across different tools. Example playbook: SIEM alert → enrich with threat intel → check reputation → if malicious: block IP on firewall + quarantine email + isolate endpoint + create ticket + notify SOC. Benefits: Faster response (MTTD/MTTR reduction), consistency (no human error in routine tasks), scalability (handle thousands of alerts), resource efficiency (analysts focus on complex cases). Guard rails: Approval workflows for high-impact actions (don't auto-delete user accounts without approval), testing in non-production, rollback capabilities, audit logging of all automated actions, human-in-the-loop for critical decisions.",
     terms:["Automation","Orchestration","SOAR","Playbook","Guard rails","Human-in-the-loop","Provisioning","Deprovisioning"],
     tasks:["Design 3 automated security playbooks","Research a SOAR platform and its orchestration capabilities","Identify 10 security tasks in your environment that could be automated"]},
   ],
   questions:[
    {q:"Isolating an infected system from the network is which IR phase?",o:["Preparation","Detection","Containment","Eradication"],a:2,x:"Containment limits the spread — network isolation is a containment action.",d:1},
    {q:"In digital forensics, which should be collected FIRST?",o:["Hard drive","RAM","Log files","Backup tapes"],a:1,x:"RAM is the most volatile — lost immediately when power is removed. Collect first per order of volatility.",d:2},
    {q:"Documented record proving evidence wasn't tampered with since collection:",o:["Baseline documentation","Chain of custody","Incident timeline","Risk register"],a:1,x:"Chain of custody documents every handler, proving evidence integrity for legal proceedings.",d:1},
    {q:"SOAR's primary benefit in security operations is:",o:["Replacing all analysts","Automating routine response to reduce MTTR","Eliminating false positives","Replacing SIEM"],a:1,x:"SOAR automates routine incident response playbooks, dramatically reducing mean time to respond.",d:2},
   ,{q:"Golden image with CIS benchmarks is:",o:["Vuln management","Secure baseline deployment","Pen test","Risk transfer"],a:1,x:"Golden images ensure systems start from hardened baseline.",d:1},{q:"BYOD vs COPE — more org control:",o:["BYOD","COPE","Equal","Neither"],a:1,x:"COPE: company owns device, full IT control.",d:1},{q:"HttpOnly cookie flag prevents:",o:["HTTP cookies","JavaScript accessing cookie","Expiration","CSRF"],a:1,x:"Prevents client-side JS from reading cookie — XSS mitigation.",d:1},{q:"NIST 800-88 Purge is for:",o:["Reuse within org","Reuse outside org (infeasible recovery)","Physical destruction","Quick format"],a:1,x:"Purge = infeasible recovery. Clear = within org. Destroy = physical.",d:2},{q:"Credentialed scan found 200, non-cred found 50. Why?",o:["Cred less accurate","Non-cred finds more","Cred checks internal configs","Misconfigured"],a:2,x:"Credentialed scans check configs, patches, software — more findings.",d:1},{q:"CVSS 4.3 classification:",o:["Low","Medium","High","Critical"],a:1,x:"Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.",d:1},{q:"Syslog over TLS port:",o:["UDP 514","TCP 514","TCP 6514","TCP 443"],a:2,x:"UDP 514 unreliable, TCP 514 reliable, TCP 6514 TLS encrypted.",d:2},{q:"MTTD measures:",o:["Time to fix","Incident to discovery","Patch deploy","Uptime"],a:1,x:"Mean Time to Detect = occurrence to discovery.",d:1},{q:"Nmap primary use:",o:["Vuln remediation","Port scanning/enumeration","Packet capture","Password cracking"],a:1,x:"Discovers open ports, services, OS detection, NSE scripting.",d:1},{q:"SPF -all means:",o:["Accept all","Soft fail","Hard fail (reject)","Neutral"],a:2,x:"-all = hard fail. ~all = soft fail (mark, dont reject).",d:2},{q:"XDR improves EDR by:",o:["Cheaper","Correlating endpoints+network+cloud+email","Endpoint only","Replacing AV"],a:1,x:"XDR breaks silos by correlating across all domains.",d:1},{q:"OAuth 2.0 is for:",o:["Authentication","Authorization","Encryption","Logging"],a:1,x:"OAuth issues access tokens for API authorization. OIDC adds auth.",d:2},{q:"Two passwords = MFA?",o:["Yes","No — same factor category","Yes if different passwords","Depends"],a:1,x:"Both knowledge = same category. Not MFA.",d:1},{q:"FIDO2/WebAuthn strongest because:",o:["SMS-based","Phishing-resistant/bound to site origin","Faster","Free"],a:1,x:"Cryptographically bound to legitimate website origin.",d:2},{q:"PAM session recording provides:",o:["Faster access","Audit trail of privileged actions","Password rules","Encryption"],a:1,x:"Captures what privileged users did — accountability + forensics.",d:1},{q:"Write blocker prevents:",o:["Reading evidence","Modifying original evidence","Network access","Encryption"],a:1,x:"Ensures original evidence not modified during forensic imaging.",d:1},{q:"First action in ransomware:",o:["Pay ransom","Wipe systems","Isolate affected systems","Call media"],a:2,x:"Containment first. Dont power off — preserves volatile evidence.",d:1},{q:"Legal hold requires:",o:["Delete data","Preserve ESI for litigation","Encrypt storage","Notify police"],a:1,x:"Preserve all relevant electronically stored information.",d:2},{q:"Guard rail in automation:",o:["Faster execution","Human approval for high-impact actions","All automated","No logging"],a:1,x:"Prevents dangerous actions without human review.",d:2},{q:"NetFlow captures:",o:["Full payload","Src/dst IP+ports+bytes+duration","Email content","File data"],a:1,x:"Flow metadata without actual packet contents.",d:2},{q:"DoH encrypts DNS over:",o:["UDP 53","TCP 853","HTTPS 443","Port 8080"],a:2,x:"DNS over HTTPS on port 443.",d:2},{q:"MAC: users change permissions?",o:["Yes owners decide","No system-enforced labels","Only admins","Depends on role"],a:1,x:"MAC uses system-enforced labels users cannot modify.",d:2},{q:"NIST recommends checking passwords against:",o:["Dictionary only","Breached password lists","Social media","Birthdays"],a:1,x:"NIST SP 800-63B: screen against known breached lists.",d:2},{q:"WPA3-Personal advantage over WPA2:",o:["Faster","SAE prevents offline dictionary attacks","Certificates","Longer passwords"],a:1,x:"SAE replaces PSK handshake, preventing offline attacks.",d:2},{q:"DKIM proves:",o:["Sender IP authorized","Email integrity via cryptographic signature","Recipient ID","Email encrypted"],a:1,x:"DKIM signs headers with private key. Receiver verifies via DNS public key.",d:2},{q:"FIM detects:",o:["Network intrusions","Unauthorized file changes","Password attacks","Social engineering"],a:1,x:"File Integrity Monitoring alerts on changes to critical system files.",d:2},{q:"SAML assertion sent from:",o:["SP to user","User to IdP","IdP to SP","RADIUS to user"],a:2,x:"Identity Provider authenticates, creates assertion, sends to Service Provider.",d:2},{q:"JIT access means:",o:["Permanent admin","Temporary elevated access, auto-revoked","Faster auth","JIT patching"],a:1,x:"Just-In-Time: privileged access only when needed, automatically revoked.",d:2},{q:"Most volatile evidence:",o:["Hard drive","Backup tapes","RAM","Log files"],a:2,x:"RAM disappears at power loss. Most volatile = collect first.",d:1},{q:"SCAP automates:",o:["Pentesting","Compliance checking against benchmarks","Password cracking","IR"],a:1,x:"SCAP uses OVAL and XCCDF for automated compliance validation.",d:2},{q:"Threat hunting vs monitoring:",o:["Automated","Proactive, hypothesis-driven","Passive","Less effective"],a:1,x:"Actively searches for threats that evade automated detection.",d:2},{q:"E-discovery is:",o:["Finding vulns","Collecting electronic evidence for legal proceedings","Network scanning","Asset inventory"],a:1,x:"Identifies, collects ESI for litigation.",d:2},{q:"After containment, next IR phase:",o:["Recovery","Lessons learned","Eradication","Preparation"],a:2,x:"NIST: Containment then Eradication then Recovery then Lessons Learned.",d:1},{q:"SOAR playbook example:",o:["Manual report","Auto-block IP after failed logins across firewalls","Quarterly assessment","Annual pentest"],a:1,x:"Automates repetitive response across multiple security tools.",d:1},{q:"Real-time cert revocation check:",o:["CRL","OCSP","OCSP stapling","Cert pinning"],a:1,x:"OCSP checks real-time. CRL is a periodically published list.",d:2},{q:"HIDS vs NIDS:",o:["Same","HIDS=host, NIDS=network traffic","HIDS newer","NIDS=host"],a:1,x:"HIDS monitors one machine. NIDS monitors network traffic.",d:1},{q:"Log retention considers:",o:["Cost only","Regulatory requirements + investigation needs + storage","Employee preference","Vendor recommendation"],a:1,x:"HIPAA=6yr, PCI=1yr, SOX=7yr. Balance with storage costs.",d:2},{q:"Anti-forensics technique:",o:["Forensic imaging","Timestomping to alter timestamps","Chain of custody","Write blockers"],a:1,x:"Timestomping modifies file timestamps to mislead investigators.",d:3},{q:"Continuous monitoring vs periodic:",o:["Same","Continuous=real-time, periodic=point-in-time","Continuous=monthly","Periodic better"],a:1,x:"Continuous=real-time compliance. Periodic=scheduled snapshots.",d:2}]},
]},
  {
  id:5, title:"Security Program Management and Oversight", weight:20, icon:"📋", color:"#a855f7",
  objectives:[
  {id:"5.1",title:"Summarize elements of effective security governance",
   topics:[
    {id:"5.1.1",title:"Security Governance Elements",
     plain:"Security governance is the hierarchy of documents guiding your program. Policies are mandatory high-level statements from executive management. Standards specify technical requirements that implement policies. Procedures are step-by-step instructions. Guidelines are recommendations that are not mandatory. Key roles: Data Owner (business executive who classifies data), Data Custodian (IT staff implementing controls), Data Steward (ensures data quality), and under GDPR the Data Controller (determines why/how data is processed) and Data Processor (processes data on behalf of the controller). The hierarchy Policy then Standard then Procedure then Guideline appears on almost every exam.",
     examTip:"Hierarchy: Policy > Standard > Procedure > Guideline. Mandatory+specific=standard. High-level+broad=policy. GDPR: Controller decides, Processor executes.",
     tech:"Hierarchy: Policies (highest level, mandatory, approved by management — AUP, Data Classification Policy, Incident Response Policy, Password Policy) → Standards (specific technical requirements implementing policies — 'passwords must be 12+ characters with MFA') → Procedures (step-by-step instructions — 'how to reset a password', 'how to handle a security incident') → Guidelines (recommendations/best practices, not mandatory — 'consider using a password manager'). Governance structures: Board of directors (overall risk oversight), CISO/CSO (security program leadership), Security committee/steering committee, Data owners, Data custodians, System owners. Roles: Data owner (classifies data, approves access — usually business executive), Data custodian (implements controls, manages day-to-day — usually IT), Data steward (ensures quality and compliance), Data processor (processes data on behalf of controller), Data controller (determines purpose and means of processing — GDPR).",
     terms:["Policy","Standard","Procedure","Guideline","CISO","Data owner","Data custodian","Data steward","Data controller","Data processor","AUP"],
     tasks:["Write sample AUP (Acceptable Use Policy)","Create the governance document hierarchy for a small company","Research CISO responsibilities and reporting structure"]},
    {id:"5.1.2",title:"Governance Frameworks",
     plain:"Frameworks are pre-built blueprints for security programs. Instead of starting from scratch, you follow a proven design. NIST CSF gives you 5 pillars (Identify, Protect, Detect, Respond, Recover). ISO 27001 gives you a certifiable management system. CIS Controls gives you a prioritized action list starting with the most impactful.",
     examTip:"NIST CSF: Identify/Protect/Detect/Respond/Recover. ISO 27001=certifiable. CIS Controls=18 prioritized in 3 IGs. PCI-DSS=12 requirements.",
     tech:"NIST CSF (Cybersecurity Framework): 5 functions — Identify (asset management, risk assessment), Protect (access control, awareness, data security), Detect (monitoring, detection processes), Respond (IR planning, communications, mitigation), Recover (recovery planning, improvements). Voluntary, widely adopted, maps to other frameworks. ISO 27001/27002: International standard. 27001 = ISMS requirements (certifiable). 27002 = security controls guidance. Plan-Do-Check-Act cycle. Requires annual surveillance audits. CIS Controls v8: 18 prioritized actions. Implementation Groups (IG1 = basic cyber hygiene, IG2 = moderate, IG3 = advanced). Starts with most impactful: Inventory (1-2), Data Protection (3), Secure Config (4), Account Mgmt (5-6). COBIT: IT governance framework — business goals to IT processes. PCI-DSS: Payment card industry — 12 requirements for handling card data. CSA CCM (Cloud Controls Matrix): Cloud-specific security framework mapping to ISO, NIST, COBIT.",
     terms:["NIST CSF","ISO 27001","ISO 27002","CIS Controls","COBIT","PCI-DSS","CSA CCM","ISMS","Implementation Groups"],
     tasks:["Download NIST CSF and map your security program to its 5 functions","Compare CIS Controls IG1 vs IG2 vs IG3","Research ISO 27001 certification process and requirements"]},
    {id:"5.1.3",title:"Regulatory and Legal Considerations",
     plain:"GDPR = EU's data protection law (huge fines). HIPAA = US healthcare data protection. PCI-DSS = credit card data security rules. SOX = financial reporting integrity. If you handle data covered by these laws, compliance is mandatory — not optional. Penalties can be millions or even billions.",
     examTip:"GDPR: 72hr notification, 4% revenue fine, right to be forgotten. HIPAA: safeguards+BAA. SOX: financial integrity. Know fine amounts.",
     tech:"GDPR (General Data Protection Regulation): EU, applies globally to EU resident data. 72-hour breach notification to authority. Fines: up to €20M or 4% global annual revenue (whichever greater). Data subject rights: access, rectification, erasure ('right to be forgotten'), portability, object to processing. Requires DPO for certain organizations. HIPAA (Health Insurance Portability and Accountability Act): US, protects PHI. Three safeguard categories: Administrative (policies, training, risk assessment), Physical (facility controls, device security), Technical (access controls, audit trails, encryption). BAA required with third parties handling PHI. PCI-DSS: 12 requirements for card data (firewalls, encryption, access control, testing, policies). Compliance levels based on transaction volume. SOX (Sarbanes-Oxley): US, financial reporting integrity. IT controls for financial systems. SOC reports. FERPA: US student educational records. CCPA/CPRA: California privacy laws.",
     terms:["GDPR","HIPAA","PCI-DSS","SOX","FERPA","CCPA","DPO","BAA","Right to be forgotten","72-hour notification"],
     tasks:["Compare GDPR vs HIPAA vs PCI-DSS in a detailed table","Research GDPR fine case studies and amounts","Create a HIPAA compliance checklist for a small medical practice"]},
   ],
   questions:[
    {q:"'Passwords must be 12+ characters with uppercase, lowercase, and numbers' is a:",o:["Policy","Standard","Procedure","Guideline"],a:1,x:"Standards specify mandatory, specific, measurable technical requirements.",d:1},
    {q:"GDPR requires breach notification to the supervisory authority within:",o:["24 hours","48 hours","72 hours","7 days"],a:2,x:"GDPR mandates notification within 72 hours of becoming aware of a breach.",d:2},
    {q:"Cloud-specific security control framework that maps to ISO and NIST:",o:["NIST CSF","CIS Controls","CSA CCM","COBIT"],a:2,x:"CSA CCM (Cloud Controls Matrix) provides cloud-specific controls mapped to major frameworks.",d:2},
    {q:"The person who classifies data and approves access requests is the:",o:["Data custodian","Data owner","Data steward","System administrator"],a:1,x:"Data owner (usually business executive) classifies data and approves access.",d:1},
   ]},
  {id:"5.2",title:"Explain elements of the risk management process",
   topics:[
    {id:"5.2.1",title:"Risk Analysis",
     plain:"Qualitative = 'this feels like HIGH likelihood and MEDIUM impact — prioritize it.' Quick and uses expert judgment. Quantitative = the insurance actuary approach: server worth $100K, 25% damage per incident, happens twice a year = $50K annual expected loss. Precise numbers, takes longer.",
     examTip:"Quantitative: AV x EF=SLE, SLE x ARO=ALE. Qualitative: High/Medium/Low matrix. Risk register documents all risks with owners.",
     tech:"Risk = Threat × Vulnerability × Impact. Qualitative: Likelihood/Impact matrix (High/Medium/Low), ordinal scales, expert judgment, fast but subjective. Heat maps for visualization. Quantitative: AV (Asset Value — $), EF (Exposure Factor — % damage per incident), SLE (Single Loss Expectancy = AV × EF), ARO (Annualized Rate of Occurrence — times/year), ALE (Annualized Loss Expectancy = SLE × ARO). Used for cost-benefit analysis of controls. Semi-quantitative: Combines both — numeric scales but not dollar values. Risk register: Central repository documenting all identified risks — description, category, likelihood, impact, risk score, owner, treatment, status, review date. Risk assessment types: Ad hoc (as needed), Recurring (scheduled), One-time (project-based), Continuous (real-time automated).",
     terms:["Risk","AV","EF","SLE","ARO","ALE","Risk matrix","Risk register","Qualitative","Quantitative","Semi-quantitative"],
     tasks:["Calculate SLE and ALE for 5 different business scenarios","Build a risk register template with 10+ entries","Create a qualitative risk matrix and plot 5 organizational risks"]},
    {id:"5.2.2",title:"Risk Management Strategies",
     plain:"Four ways to handle risk: Accept (we know about it and choose to live with it — documented). Avoid (stop doing the risky activity entirely). Transfer (buy insurance or outsource). Mitigate (add controls to reduce the risk). The goal is to get residual risk within your appetite.",
     examTip:"Accept, Avoid, Transfer, Mitigate. Residual risk must be within appetite. Insurance=transfer. KRIs indicate increasing risk.",
     tech:"Risk strategies: Accept/tolerance (documented decision — risk within appetite, signed by risk owner), Avoid/Eliminate (stop the activity creating the risk — shut down risky service), Transfer/sharing (insurance, outsourcing, contractual — SLA penalties), Mitigate/reduce (implement controls to reduce likelihood or impact). Residual risk: Risk remaining AFTER controls are applied. Must be within risk appetite. If residual > appetite, additional controls needed. Inherent risk: Risk before any controls. Risk appetite: Amount of risk organization is willing to accept (board-level decision). Risk tolerance: Acceptable deviation from risk appetite. Key Risk Indicators (KRIs): Metrics that indicate increasing risk — number of unpatched systems, phishing click rate, policy exceptions, days since last backup test.",
     terms:["Risk acceptance","Risk avoidance","Risk transfer","Risk mitigation","Residual risk","Inherent risk","Risk appetite","Risk tolerance","KRI"],
     tasks:["Design risk treatment plans for 5 identified risks","Compare cyber insurance policies for coverage and exclusions","Define risk appetite statement for a fictional organization"]},
    {id:"5.2.3",title:"Business Impact Analysis (BIA)",
     plain:"A BIA answers: 'If this system goes down, how bad is it?' It identifies your most critical business functions, how quickly they need to be restored (RTO), and how much data loss is tolerable (RPO). It's the foundation for your disaster recovery plan because it tells you what to protect first.",
     examTip:"BIA identifies critical functions and RTO/RPO. Single points of failure. MEFs=must continue during disruption. BIA feeds DR planning.",
     tech:"BIA process: 1) Identify critical business functions and processes. 2) Determine impact of disruption (financial, operational, legal, reputational). 3) Establish recovery priorities. 4) Define RTO (max downtime) and RPO (max data loss) per function. 5) Identify dependencies (systems, personnel, vendors, facilities). 6) Document single points of failure. Impact types: Financial (lost revenue, penalties, recovery costs), Operational (productivity loss, customer impact), Legal/regulatory (compliance violations, lawsuits), Reputational (brand damage, customer trust). Mission Essential Functions (MEFs): Functions that must continue during any disruption. COOP (Continuity of Operations Plan): Maintaining essential functions during crisis. Succession planning: Who takes over if key personnel are unavailable.",
     terms:["BIA","RTO","RPO","Critical business function","Single point of failure","MEF","COOP","Succession planning"],
     tasks:["Conduct a BIA for a small business identifying top 5 critical functions","Define RTO/RPO for each identified function","Create a succession planning document for key security roles"]},
   ],
   questions:[
    {q:"Server worth $200K, 25% EF, 0.5 ARO. Annual Loss Expectancy =",o:["$25,000","$50,000","$100,000","$200,000"],a:0,x:"SLE = $200K × 0.25 = $50K. ALE = $50K × 0.5 = $25K per year.",d:3},
    {q:"Risk remaining after all controls are applied:",o:["Inherent risk","Residual risk","Risk appetite","Control risk"],a:1,x:"Residual risk is what remains after mitigation. Must be within risk appetite.",d:1},
    {q:"Completely stopping an online service due to unacceptable risk:",o:["Risk acceptance","Risk mitigation","Risk transfer","Risk avoidance"],a:3,x:"Risk avoidance eliminates risk by eliminating the activity.",d:1},
    {q:"BIA's PRIMARY purpose is to:",o:["List all vulnerabilities","Identify critical functions and recovery priorities","Test backup systems","Assess employee performance"],a:1,x:"BIA identifies critical business functions and determines their recovery requirements (RTO/RPO).",d:1},
   ]},
  {id:"5.3",title:"Explain the processes associated with third-party risk assessment and management",
   topics:[
    {id:"5.3.1",title:"Third-party Risk Assessment",
     plain:"Third-party risk = vetting a babysitter: check references (SOC 2 reports), verify background (vendor questionnaires), set rules (SLAs), sign agreements (NDAs), and reserve the right to check in anytime (right-to-audit clause). Your vendor's weakness is YOUR weakness.",
     examTip:"Third-party risk: check SOC 2 reports, right-to-audit clause, supply chain verification. Ongoing monitoring not just initial assessment.",
     tech:"Assessment methods: Vendor questionnaires (standardized security questions — SIG, CAIQ), SOC reports (SOC 1: financial controls, SOC 2 Type I: control design at a point in time, SOC 2 Type II: control effectiveness over 6-12 months — PREFERRED), Right-to-audit clauses (contractual right to perform your own assessment), Penetration test results, Compliance certifications (ISO 27001, PCI-DSS). Supply chain analysis: SBOM (Software Bill of Materials), hardware provenance, trusted suppliers. Ongoing monitoring: Continuous vendor risk scoring (BitSight, SecurityScorecard), breach notification requirements, periodic reassessment schedule. Risk considerations: Data handling practices, geographic locations (data sovereignty), subcontractor/fourth-party risks, financial stability, incident response capabilities, exit strategy (data return/destruction).",
     terms:["SOC 2 Type II","Right-to-audit","Vendor questionnaire","SBOM","SIG","Fourth-party risk","Vendor risk scoring"],
     tasks:["Review a SOC 2 Type II report structure and key sections","Draft a vendor security questionnaire with 20 key questions","Research vendor risk scoring platforms"]},
    {id:"5.3.2",title:"Agreement Types",
     plain:"Business agreements are legal rules of engagement. SLA defines measurable guarantees (99.9% uptime) with financial penalties for failure. NDA protects confidential information shared between parties. MOU states mutual intent but is less legally binding than a formal contract. MSA is the umbrella agreement covering the overall relationship with specific SOWs underneath for each project. BPA defines the business partnership terms. ISA defines security requirements when connecting two organizations networks - common in government. For the exam memorize: 99.9%=8.7hrs downtime/year, 99.99%=52min, 99.999%=5.26min.",
     examTip:"SLA math: 99.9%=8.7hrs, 99.99%=52min, 99.999%=5.26min per year. MOU=less binding. ISA=network interconnection security.",
     tech:"Agreement types: SLA (Service Level Agreement — measurable performance requirements: uptime %, response time, resolution time, penalties for non-compliance), MOU (Memorandum of Understanding — statement of intent between parties, less formal/binding than contract), MOA (Memorandum of Agreement — more formal than MOU, binding), NDA (Non-Disclosure Agreement — protects confidential information, unilateral or bilateral), BPA (Business Partner Agreement — defines partner relationship, responsibilities, profit sharing), MSA (Master Service Agreement — umbrella terms governing overall relationship, individual SOWs underneath), ISA (Interconnection Security Agreement — security requirements for connecting two organizations' networks — common in government). Key SLA metrics: Uptime (99.9% = 8.7hrs downtime/year, 99.99% = 52min), MTTR, response time tiers by severity.",
     terms:["SLA","MOU","MOA","NDA","BPA","MSA","ISA","SOW","Uptime guarantee"],
     tasks:["Compare SLA vs MOU vs MSA with examples","Draft an NDA template","Calculate downtime allowances for different uptime SLAs"]},
   ],
   questions:[
    {q:"SOC report evaluating control effectiveness over 6-12 months:",o:["SOC 1 Type I","SOC 2 Type I","SOC 2 Type II","SOC 3"],a:2,x:"SOC 2 Type II evaluates control design AND operating effectiveness over a period of time.",d:2},
    {q:"Complete inventory of all open-source libraries in a software product:",o:["CMDB","SBOM","Asset register","CVE list"],a:1,x:"SBOM (Software Bill of Materials) lists all software components and dependencies.",d:1},
    {q:"Agreement defining measurable uptime requirements with financial penalties:",o:["NDA","MOU","SLA","BPA"],a:2,x:"SLA specifies measurable performance requirements with consequences for non-compliance.",d:1},
   ]},
  {id:"5.4",title:"Summarize elements of effective security compliance",
   topics:[
    {id:"5.4.1",title:"Compliance Monitoring and Reporting",
     plain:"Compliance = following the rules (laws, regulations, industry standards) and proving it through documentation and audits. Non-compliance consequences: fines ($$$), lawsuits, lost business, reputation damage, criminal penalties. Continuous monitoring ensures you don't just pass the audit but stay compliant year-round.",
     examTip:"GDPR=20M EUR/4%. HIPAA=50K-1.5M per violation. PCI-DSS=5K-100K/month. Attestation=formal compliance declaration.",
     tech:"Compliance types: Regulatory (GDPR, HIPAA, SOX — legal requirement), Industry (PCI-DSS — contractual requirement), Internal (organizational policies). Monitoring: Continuous compliance monitoring (automated scanning against requirements), periodic assessments, self-audits, exception tracking. Reporting: Compliance dashboards, regulatory reports, board reports, audit findings, remediation tracking. Consequences of non-compliance: Financial penalties (GDPR: €20M/4% revenue; HIPAA: $50K-$1.5M per violation category; PCI-DSS: $5K-$100K per month), Legal action, Loss of business relationships, Reputational damage, Loss of certifications, Criminal prosecution (SOX). Attestation: Formal declaration of compliance by authorized individual. Sign-off on compliance status.",
     terms:["Compliance monitoring","Attestation","Regulatory compliance","Industry compliance","Non-compliance penalties","Compliance dashboard"],
     tasks:["Research actual GDPR and HIPAA fine amounts from recent cases","Create a compliance monitoring checklist","Design a compliance dashboard showing key metrics"]},
    {id:"5.4.2",title:"Privacy",
     plain:"Privacy is about giving people control over THEIR data. GDPR gives EU citizens the right to know what data you have, correct it, delete it (right to be forgotten), and take it with them (data portability). Privacy Impact Assessments evaluate how new projects will affect personal data.",
     examTip:"GDPR rights: access, rectify, erase, portability, restrict, object. Data minimization=collect only needed. PIA/DPIA=privacy assessments.",
     tech:"Privacy principles: Data minimization (collect only what's needed), Purpose limitation (use only for stated purpose), Storage limitation (keep only as long as needed), Accuracy, Lawful processing, Transparency. Data subject rights (GDPR): Right of access, Right to rectification, Right to erasure ('right to be forgotten'), Right to data portability, Right to restrict processing, Right to object. Data roles: Controller (determines purpose/means of processing), Processor (processes data on behalf of controller — must have DPA/Data Processing Agreement), DPO (Data Protection Officer — required for certain organizations under GDPR). Privacy assessments: PIA (Privacy Impact Assessment — general privacy evaluation), DPIA (Data Protection Impact Assessment — required under GDPR for high-risk processing). Data inventory and retention: Know what data you have, where it's stored, who has access, retention schedule, secure disposal.",
     terms:["Data minimization","Right to be forgotten","Data portability","PIA","DPIA","DPO","Data controller","Data processor","Retention schedule"],
     tasks:["Create a data inventory for a fictional company","Write a privacy policy following GDPR requirements","Research when DPIA is required under GDPR"]},
    {id:"5.4.3",title:"Audits and Assessments",
     plain:"Audits = inspection day. Internal audit = your own team checking everything. External audit = hiring an outside inspector (more credible). Regulatory audit = the government inspector shows up (scariest). The goal is to find gaps BEFORE the bad guys (or regulators) do.",
     examTip:"Internal audit=your team. External=independent third party. SOC 2 Type I=design. Type II=operating effectiveness over time.",
     tech:"Audit types: Internal (self-assessment by internal audit team — frequent, less formal, identifies issues early), External (independent third-party — more credible for stakeholders, required for some certifications), Regulatory (government/authority — mandatory, non-compliance = penalties). Audit scope: Financial controls (SOC 1), Security controls (SOC 2), Privacy, Compliance with specific regulations. Assessment methods: Interviews, documentation review, technical testing, observation, sampling. Attestation: Formal statement by auditor or management about compliance status. Different from assertion (claim) vs attestation (verification). Certification audits: ISO 27001 (Stage 1 = documentation review, Stage 2 = effectiveness assessment), SOC 2 (Type I = design, Type II = effectiveness over time), PCI-DSS (ROC/SAQ).",
     terms:["Internal audit","External audit","Regulatory audit","Attestation","SOC 2","ISO 27001 certification","ROC","SAQ"],
     tasks:["Create an internal audit checklist for access controls","Research ISO 27001 Stage 1 and Stage 2 audit process","Compare SOC 2 Type I vs Type II reports in detail"]},
   ],
   questions:[
    {q:"Under GDPR, the entity that determines the purpose and means of data processing is the:",o:["Data processor","Data controller","Data custodian","Data steward"],a:1,x:"Data controller decides WHY and HOW personal data is processed.",d:2},
    {q:"Maximum GDPR fine for severe violations:",o:["€10M or 2% revenue","€20M or 4% revenue","€50M flat","$100M or 5% revenue"],a:1,x:"Up to €20M or 4% of annual global turnover, whichever is greater.",d:2},
    {q:"Due care vs due diligence:",o:["Same thing","Due care = research, due diligence = ongoing effort","Due diligence = research before, due care = ongoing reasonable effort","Due care = legal, due diligence = technical"],a:2,x:"Due diligence = research/investigation before decisions. Due care = ongoing reasonable effort to maintain protection.",d:2},
   ]},
  {id:"5.5",title:"Explain types and purposes of audits and assessments",
   topics:[
    {id:"5.5.1",title:"Penetration Testing for Compliance",
     plain:"Penetration testing for compliance is a formal documented assessment required by frameworks like PCI-DSS (annual external and internal pentest) and recommended by ISO 27001. The Rules of Engagement define exactly what can be tested, when, which techniques are authorized, and emergency contacts. Written authorization is mandatory - without it, its legally just hacking. Vulnerability assessment scans and reports weaknesses without exploitation. Penetration testing actually exploits vulnerabilities to prove impact. Red team simulates real attacker TTPs against the entire organization testing detection capabilities. Blue team defends. Purple team works collaboratively sharing findings in real-time.",
     examTip:"Vuln assessment=scan only. Pentest=exploit. Red team=simulate real attacker TTPs. Always written authorization. Know the differences.",
     tech:"Penetration test types (same as 4.3.3 but compliance focus): Required by many regulations/standards — PCI-DSS (annual external and internal pentest), HIPAA (periodic technical evaluation), ISO 27001 (as part of risk assessment). Compliance pentest requirements: Written authorization (legal protection), Defined scope (which systems, from which perspective), Rules of engagement (timing, techniques allowed, escalation procedures, emergency contacts), Qualified testers (certifications: OSCP, CEH, GPEN, PenTest+), Report requirements (executive summary, technical findings, evidence, remediation recommendations, re-test plan). Red team vs pentest: Pentest = find as many vulnerabilities as possible in defined scope. Red team = simulate real attacker TTPs against the entire organization, test detection and response. Blue team = defenders. Purple team = combined, collaborative improvement.",
     terms:["Pentest compliance","Rules of engagement","Written authorization","Red team","Blue team","Purple team","OSCP"],
     tasks:["Write a complete Rules of Engagement template","Research PCI-DSS penetration testing requirements","Compare pentest vs red team vs vulnerability assessment"]},
   ],
   questions:[
    {q:"Pen test where tester simulates real attacker TTPs against entire organization, testing detection capabilities:",o:["Vulnerability assessment","Compliance pentest","Red team exercise","Bug bounty"],a:2,x:"Red team exercises simulate real-world attacks to test the organization's detection and response.",d:2},
   ]},
  {id:"5.6",title:"Given a scenario, implement security awareness practices",
   topics:[
    {id:"5.6.1",title:"Security Awareness Programs",
     plain:"You can have the best firewalls in the world, but if an employee clicks a phishing link, it's game over. Security awareness training turns employees from the weakest link into human firewalls. Phishing simulations test who clicks — repeat offenders get extra training.",
     examTip:"Phishing sims measure behavior change. Target under 5% click rate. Encourage reporting. Dont punish clicking.",
     tech:"Awareness program components: Phishing simulations (send fake phishing to employees, track click rates, provide immediate training on failure — tools: GoPhish, KnowBe4, Proofpoint), Anomalous behavior recognition (train employees to identify unusual requests, social engineering attempts, insider threat indicators), Reporting mechanisms (easy way to report suspicious emails — phishing button, incident hotline, anonymous reporting), Ongoing training (initial onboarding + annual refresher + role-specific advanced), Gamification (rewards for reporting, competitions between departments). Training topics: Phishing identification, password security, physical security, social engineering, data handling, clean desk policy, mobile device security, social media risks, incident reporting procedures. Metrics: Phishing click rate (goal: <5%), training completion rate, incident reporting rate, policy acknowledgment.",
     terms:["Security awareness","Phishing simulation","Anomalous behavior","Clean desk","Reporting mechanism","Click rate","KnowBe4"],
     tasks:["Design a security awareness program with quarterly activities","Create a phishing simulation campaign with GoPhish","Develop security awareness training materials for new employees"]},
    {id:"5.6.2",title:"User Training Best Practices",
     plain:"The best training is relevant, engaging, and frequent — not a boring annual slideshow nobody remembers. Role-based training means the CFO gets training about BEC/wire fraud, developers get secure coding, and everyone gets phishing awareness. Measure results — if the click rate isn't dropping, change the training.",
     examTip:"Role-based: execs get BEC training, devs get OWASP, all get phishing. Micro-learning > annual 8-hour marathon.",
     tech:"Training delivery: Computer-based (CBT), instructor-led, micro-learning (short modules), just-in-time (triggered by events — failed phishing sim triggers immediate training), hands-on exercises. Role-based training: General (all employees — phishing, passwords, physical), Executive (BEC, data privacy, risk decisions), IT staff (secure configuration, incident handling), Developers (secure coding, OWASP Top 10), Privileged users (PAM, audit requirements). Development lifecycle: Onboarding (initial comprehensive), Ongoing (quarterly micro-learning), Annual (full refresher), Incident-triggered (after security events), Role change (when responsibilities change). Metrics and improvement: Track completion, test scores, phishing simulation results, policy violations, incident reporting rates. Benchmark against industry. Continuously improve content based on results.",
     terms:["Role-based training","CBT","Micro-learning","Just-in-time training","Gamification","Training metrics","Onboarding training"],
     tasks:["Create role-specific training outlines for 3 different roles","Design metrics dashboard for security awareness program","Research effective security awareness programs and their measured impact"]},
   ],
   questions:[
    {q:"Best metric to measure phishing awareness training effectiveness:",o:["Training completion rate","Employee satisfaction survey","Phishing simulation click rate over time","Number of policies signed"],a:2,x:"Phishing click rate trends directly measure whether employees can identify phishing in practice.",d:1},
    {q:"CFO receives targeted training about wire fraud and BEC. This is an example of:",o:["General awareness","Role-based training","Compliance training","Remedial training"],a:1,x:"Role-based training provides content specific to the person's job responsibilities and threat exposure.",d:1},
   ,{q:"Policy vs standard:",o:["Policies optional","Policies=intent, standards=requirements","Standards higher level","Same thing"],a:1,x:"Policy = high-level intent. Standard = specific measurable requirements.",d:1},{q:"NIST CSF five functions:",o:["Identify/Protect/Detect/Respond/Recover","Assess/Mitigate/Monitor/Report/Review","Plan/Do/Check/Act/Review","Prevent/Detect/Analyze/Contain/Recover"],a:0,x:"NIST CSF: Identify→Protect→Detect→Respond→Recover.",d:1},{q:"HIPAA BAA required when:",o:["Employee accesses records","Third party handles PHI","New software","International travel"],a:1,x:"BAA required when third party creates/receives/maintains/transmits PHI.",d:2},{q:"SLE=$500K ARO=0.2 ALE=:",o:["$100,000","$500,000","$250,000","$2,500,000"],a:0,x:"ALE=SLE×ARO=$500K×0.2=$100K/year.",d:2},{q:"Cyber insurance is which strategy?",o:["Acceptance","Avoidance","Mitigation","Transfer"],a:3,x:"Insurance transfers financial impact to third party.",d:1},{q:"RTO of 4 hours means:",o:["Data 4hrs old","Restored within 4hrs","Backup every 4hrs","Test every 4hrs"],a:1,x:"RTO = max acceptable downtime.",d:1},{q:"SOC 2 Type II minimum period:",o:["1 month","3 months","6 months","12 months"],a:2,x:"Min 6 months, typically 12 months evaluation.",d:2},{q:"99.99% uptime yearly downtime:",o:["8.7 hours","52 minutes","5.2 minutes","26 minutes"],a:1,x:"99.99%=~52min. 99.9%=8.7hrs. 99.999%=5.26min.",d:2},{q:"DPIA required under GDPR when:",o:["Any data","High-risk processing","New hire","Budget approved"],a:1,x:"Required for profiling, large-scale sensitive data processing.",d:2},{q:"Phishing click rate 25%→8% shows:",o:["Technical controls","Awareness program effectiveness","Policy compliance","Vendor improvement"],a:1,x:"Declining rates directly measure behavior change.",d:1},{q:"Purple team =:",o:["External only","Red+blue collaborating","Auditors","Management"],a:1,x:"Red (attack) + blue (defend) improving defenses together.",d:2},{q:"SBOM mitigates:",o:["Physical security","Supply chain vulnerability","Social engineering","DDoS"],a:1,x:"Lists all components, identifying vulnerable libraries.",d:1},{q:"Residual risk exceeding appetite requires:",o:["Shutdown","Additional controls or leadership acceptance","No action","Termination"],a:1,x:"More controls or formal leadership risk acceptance.",d:2},{q:"ISO 27001 maintenance:",o:["Self-assessment","Annual surveillance audits","Quarterly pentests","Monthly scans"],a:1,x:"Annual surveillance + full recertification every 3 years.",d:2},{q:"MOU vs contract:",o:["More detailed","Statement of intent, less binding","Requires notary","Has penalties"],a:1,x:"MOU = mutual intent, less enforceable than formal contract.",d:1},{q:"CIS Controls IG1 represents:",o:["Advanced","Basic cyber hygiene","Military-grade","Cloud-only"],a:1,x:"IG1 = essential hygiene. IG2 = moderate. IG3 = advanced.",d:1},{q:"Risk register includes:",o:["Description only","Description, likelihood, impact, owner, treatment, status","Financial only","Technical only"],a:1,x:"Living document with analysis, owner, treatment plan, review dates.",d:1},{q:"Due diligence vs due care:",o:["Same","Diligence=research before, care=ongoing effort","Care=legal","Diligence stricter"],a:1,x:"Diligence = investigate before decisions. Care = ongoing reasonable effort.",d:2},{q:"KRI example:",o:["Employee count","Percent unpatched critical systems","Temperature","Revenue"],a:1,x:"KRIs indicate increasing risk: unpatched systems, click rates, exceptions.",d:2},{q:"ALE helps justify:",o:["Bonuses","Control investment by comparing to control cost","Renovations","Hiring"],a:1,x:"ALE=$100K, control=$30K/year = clear ROI for the investment.",d:2},{q:"PCI-DSS applies when:",o:["Use email","Process/store/transmit card data","Have website","100+ employees"],a:1,x:"Any entity handling cardholder data. Level based on transaction volume.",d:1},{q:"GDPR data controller:",o:["Processes for others","Determines purpose and means of processing","Stores in cloud","Destroys data"],a:1,x:"Controller decides WHY and HOW. Processor acts on instructions.",d:2},{q:"SOC 1 vs SOC 2:",o:["Same","SOC 1=financial, SOC 2=security/availability/privacy","SOC 2 older","SOC 1 better"],a:1,x:"SOC 1 = ICFR. SOC 2 = Trust Services Criteria.",d:2},{q:"Fourth-party risk:",o:["Fourth employee","Your vendors vendors","Fourth assessment type","Risk level 4"],a:1,x:"Subcontractor risk flows up to you through your vendor.",d:2},{q:"CCPA/CPRA applies to:",o:["All US","California consumer data","EU only","Healthcare only"],a:1,x:"California consumer privacy. Similar to but different from GDPR.",d:1},{q:"Succession planning:",o:["Promote all","Document who takes key security roles if unavailable","Hiring","Retirement"],a:1,x:"Ensures security leadership continuity.",d:2},{q:"Data retention schedule:",o:["Backup speed","How long data kept before disposal","Who accesses","Where stored"],a:1,x:"Balance regulatory requirements with storage. Over-retention increases risk.",d:1},{q:"Security awareness MOST effective:",o:["Annual 8hr","Frequent short modules with simulations","Policy reading","One-time onboarding"],a:1,x:"Micro-learning with real-world simulations beats annual marathon.",d:1},{q:"COOP ensures:",o:["IT backup","Essential functions continue during disruption","Vacation coverage","Vendor mgmt"],a:1,x:"Continuity of Operations maintains Mission Essential Functions.",d:2},{q:"Vendor risk scoring provides:",o:["Free tools","Continuous external security posture assessment","Pentesting","Certification"],a:1,x:"BitSight/SecurityScorecard score vendors from external signals.",d:2}]},
]},
]}

// ═══ PBQ SCENARIOS ═══
const PBQS = [
  { id:"pbq1", title:"🖥️ Firewall Rule Configuration", domain:3, diff:3,
    scenario:"Your web server (192.168.1.100) in the DMZ needs: HTTPS (443) from internet, SSH (22) from internal (10.0.0.0/24) only. ALL other DMZ traffic denied. Select correct rules in order (top-down processing).",
    rules:[
      {id:"r1",text:"ALLOW ANY → 192.168.1.100:443 (HTTPS)",correct:true,order:1},
      {id:"r2",text:"ALLOW 10.0.0.0/24 → 192.168.1.100:22 (SSH)",correct:true,order:2},
      {id:"r3",text:"DENY ANY → 192.168.1.0/24 (Block all other DMZ)",correct:true,order:3},
      {id:"r4",text:"ALLOW ANY → 192.168.1.100:22 (SSH from anywhere)",correct:false},
      {id:"r5",text:"ALLOW ANY → ANY (Permit all)",correct:false},
      {id:"r6",text:"ALLOW 10.0.0.0/24 → 192.168.1.100:80 (HTTP)",correct:false},
    ],
    explain:"Allow HTTPS publicly, restrict SSH to internal, deny everything else. SSH from anywhere violates requirements. Permit all is dangerous. HTTP wasn't requested."
  },
  { id:"pbq2", title:"📋 Log Analysis — Identify the Attack", domain:4, diff:2,
    scenario:"Web server logs:\n[14:22:01] GET /index.php?id=1 OR 1=1-- HTTP/1.1 200\n[14:22:03] GET /index.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1 200\n[14:22:05] GET /index.php?id=1; DROP TABLE users;-- HTTP/1.1 500\n\nIdentify the attack, indicator, and mitigation.",
    options:[
      {id:"a1",text:"SQL Injection — SQL syntax in URL params — Parameterized queries + WAF",correct:true},
      {id:"a2",text:"XSS — JavaScript in URL — Output encoding + CSP",correct:false},
      {id:"a3",text:"Directory Traversal — Path manipulation — Input validation",correct:false},
      {id:"a4",text:"Brute Force — Rapid requests — Rate limiting",correct:false},
    ],
    explain:"Classic SQLi: OR 1=1 (bypass), UNION SELECT (extraction), DROP TABLE (destruction). Primary fix: parameterized queries."
  },
  { id:"pbq3", title:"🚨 Incident Response — Ransomware", domain:4, diff:3,
    scenario:"Monday morning: files show .encrypted extension with ransom note across 15 workstations and file server. Last backup: Friday 11PM. You are IR lead. Order these actions per NIST SP 800-61:",
    steps:[
      {id:"s1",text:"Isolate affected systems from network (don't power off)",order:1,phase:"Containment"},
      {id:"s2",text:"Capture RAM images before shutdown (volatile evidence)",order:2,phase:"Evidence"},
      {id:"s3",text:"Identify patient zero and attack vector",order:3,phase:"Analysis"},
      {id:"s4",text:"Remove malware, patch vuln, reset compromised creds",order:4,phase:"Eradication"},
      {id:"s5",text:"Restore from Friday backup, verify integrity, monitor",order:5,phase:"Recovery"},
      {id:"s6",text:"Post-incident review, update IR plan, improve controls",order:6,phase:"Lessons Learned"},
    ],
    explain:"CONTAIN first (isolate), PRESERVE evidence (RAM), ANALYZE (root cause), ERADICATE, RECOVER (Friday backup = ~61hr RPO), REVIEW. Never pay ransom as first action."
  },
,
  { id:"pbq4", title:"\ud83d\udd10 ACL Configuration \u2014 File Server", domain:4, diff:2,
    scenario:"Configure NTFS permissions:\n- HR: HR=Read/Write, Managers=Read, Others=None\n- Finance: Finance=Read/Write, Auditors=Read, Others=None\n- Public: All=Read, IT Admins=Full Control\n\nSelect CORRECT assignments:",
    rules:[{id:"a1",text:"HR \u2192 HR:Modify, Managers:Read, Deny others",correct:true},{id:"a2",text:"Finance \u2192 Finance:Modify, Auditors:Read, Deny others",correct:true},{id:"a3",text:"Public \u2192 Domain Users:Read, IT Admins:Full",correct:true},{id:"a4",text:"HR \u2192 Everyone:Full Control",correct:false},{id:"a5",text:"Finance \u2192 Auditors:Modify",correct:false},{id:"a6",text:"Public \u2192 Everyone:Modify",correct:false}],
    explain:"Least privilege: minimum access per role. Everyone:Full violates this. Auditors need Read only for independence."
  },
  { id:"pbq5", title:"\ud83d\udce7 Email Security \u2014 SPF/DKIM/DMARC", domain:4, diff:3,
    scenario:"Set up email auth for company.com:\n- Mail from: 198.51.100.25 and Mailchimp\n- Reject ALL failing emails\n\nSelect correct DNS records:",
    rules:[{id:"e1",text:"SPF: v=spf1 ip4:198.51.100.25 include:mchimpmail.com -all",correct:true},{id:"e2",text:"DKIM: TXT with public key at selector._domainkey",correct:true},{id:"e3",text:"DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@company.com",correct:true},{id:"e4",text:"SPF: v=spf1 +all (accept all)",correct:false},{id:"e5",text:"DMARC: p=none (monitor only)",correct:false},{id:"e6",text:"SPF: missing Mailchimp include",correct:false}],
    explain:"SPF includes both sources with -all. DKIM key in DNS. DMARC p=reject enforces. +all defeats purpose."
  },
  { id:"pbq6", title:"\ud83c\udf10 Network Segmentation \u2014 Hospital", domain:3, diff:3,
    scenario:"Segment hospital network:\n- Medical IoT isolated\n- Patient records from clinical only\n- Guest WiFi no internal access\n- Admin access to all internal\n\nSelect correct rules:",
    rules:[{id:"n1",text:"IoT \u2192 Separate VLAN, deny outbound to others",correct:true},{id:"n2",text:"Patient records \u2192 Clinical VLAN only via 443",correct:true},{id:"n3",text:"Guest \u2192 Isolated VLAN, internet-only",correct:true},{id:"n4",text:"Admin \u2192 Management VLAN, controlled internal access",correct:true},{id:"n5",text:"IoT \u2192 Same VLAN as clinical",correct:false},{id:"n6",text:"Guest \u2192 Bridge to internal with MAC filtering",correct:false},{id:"n7",text:"Patient records \u2192 All VLANs for convenience",correct:false}],
    explain:"IoT isolated. Guest internet-only. Records restricted. MAC filtering spoofable. Convenience never trumps HIPAA."
  },
  { id:"pbq7", title:"\ud83d\udd11 Certificate Troubleshooting", domain:1, diff:2,
    scenario:"Users see ERR_CERT_DATE_INVALID on portal.company.com.\nCert issued to: portal.company.com by Internal CA\nValid: Jan 2024 - Jan 2025. Today: Feb 2026.\nInternal CA trusted on domain machines.\n\nIdentify the problem:",
    options:[{id:"c1",text:"Certificate expired Jan 2025 \u2014 Renew it",correct:true},{id:"c2",text:"Wrong domain name",correct:false},{id:"c3",text:"Self-signed \u2014 buy public CA cert",correct:false},{id:"c4",text:"Missing intermediate CA",correct:false}],
    explain:"Expired over a year. Domain matches, CA trusted, not self-signed. Renew + automate renewal."
  },
  { id:"pbq8", title:"\ud83d\udcca Quantitative Risk Analysis", domain:5, diff:3,
    scenario:"Server value: $150K, outage once/2 years, 30% damage each.\nCalculate SLE, ARO, ALE:",
    options:[{id:"r1",text:"SLE=$45K (150K\u00d730%), ARO=0.5, ALE=$22,500/yr",correct:true},{id:"r2",text:"SLE=$150K, ARO=1, ALE=$150K/yr",correct:false},{id:"r3",text:"SLE=$50K, ARO=0.5, ALE=$25K/yr",correct:false},{id:"r4",text:"SLE=$45K, ARO=2, ALE=$90K/yr",correct:false}],
    explain:"SLE=AV\u00d7EF=$150K\u00d70.30=$45K. ARO=1/2yrs=0.5. ALE=$45K\u00d70.5=$22,500. ARO=2 means twice/year."
  },
  { id:"pbq9", title:"\ud83d\udee1\ufe0f Wireless Security \u2014 Enterprise", domain:4, diff:3,
    scenario:"Configure WPA3-Enterprise:\n- Mutual cert auth, RADIUS at 10.0.1.50\n- Guest WiFi with portal, rogue AP detection\n\nSelect correct config:",
    rules:[{id:"w1",text:"EAP-TLS (mutual certificate auth)",correct:true},{id:"w2",text:"RADIUS: 10.0.1.50 port 1812",correct:true},{id:"w3",text:"Guest: Isolated VLAN, captive portal, no internal",correct:true},{id:"w4",text:"WIDS/WIPS for rogue detection",correct:true},{id:"w5",text:"PEAP-MSCHAPv2 (server cert only)",correct:false},{id:"w6",text:"Guest: Same VLAN, MAC filtering",correct:false},{id:"w7",text:"WPA2-Personal with passphrase",correct:false}],
    explain:"EAP-TLS=mutual certs (strongest). PEAP=server only. Guest isolated. WIDS detects rogues. WPA2-PSK not enterprise."
  },
  { id:"pbq10", title:"\ud83d\udea8 Data Breach \u2014 GDPR Response", domain:4, diff:3,
    scenario:"50GB exfiltrated from HR database with PII/SSNs. Subject to GDPR.\nOrder response actions:",
    steps:[{id:"b1",text:"Isolate HR server, block external IP",order:1,phase:"Containment"},{id:"b2",text:"Capture forensic images, preserve evidence",order:2,phase:"Evidence"},{id:"b3",text:"Determine scope: what data, how many affected",order:3,phase:"Analysis"},{id:"b4",text:"Notify legal, start GDPR 72hr clock",order:4,phase:"Notification"},{id:"b5",text:"Patch vuln, revoke credentials, harden",order:5,phase:"Eradication"},{id:"b6",text:"Restore backup, monitor, notify individuals",order:6,phase:"Recovery"},{id:"b7",text:"Post-incident review, add DLP",order:7,phase:"Lessons Learned"}],
    explain:"CONTAIN\u2192EVIDENCE\u2192ANALYZE\u2192NOTIFY (72hr)\u2192ERADICATE\u2192RECOVER\u2192REVIEW."
  }
];

// ═══ ENGINE FUNCTIONS ═══
const allTopics = () => DB.domains.flatMap(d=>d.objectives.flatMap(o=>o.topics));
const allQuestions = () => DB.domains.flatMap(d=>d.objectives.flatMap(o=>o.questions||[]));
const XP={topic:60,quiz:35,perfect:120,task:45,pbq:150,shadow:500};
const RANKS=[
  {lv:1,t:"Recruit",xp:0,b:"🐣"},{lv:2,t:"Analyst Trainee",xp:250,b:"🔰"},
  {lv:3,t:"SOC Analyst I",xp:600,b:"🛡️"},{lv:4,t:"SOC Analyst II",xp:1200,b:"⚔️"},
  {lv:5,t:"Security Engineer",xp:2200,b:"🔧"},{lv:6,t:"Pen Tester",xp:3500,b:"💉"},
  {lv:7,t:"Threat Hunter",xp:5000,b:"🎯"},{lv:8,t:"Security Architect",xp:7000,b:"🏗️"},
  {lv:9,t:"CISO",xp:9500,b:"👔"},{lv:10,t:"Security+ Certified!",xp:12500,b:"🏆"},
];
const getRank=(xp)=>{let c=RANKS[0];for(const r of RANKS){if(xp>=r.xp)c=r;else break;}const ni=RANKS.findIndex(r=>r.lv===c.lv)+1;const n=ni<RANKS.length?RANKS[ni]:null;const p=n?Math.min(((xp-c.xp)/(n.xp-c.xp))*100,100):100;return{...c,n,p,xp};};
const shadowQ=(q)=>{const p=["In a multi-layered enterprise, ","Given defense-in-depth requirements, ","A senior analyst must determine: ","Considering NIST guidelines, "];return{...q,q:p[Math.floor(Math.random()*p.length)]+q.q.charAt(0).toLowerCase()+q.q.slice(1),shadow:true};};


// ═══ LOCALSTORAGE HELPERS ═══
const LS_KEY = "nexus_core_save";
const loadSave = () => {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) return JSON.parse(raw);
  } catch (e) { console.warn("Failed to load save:", e); }
  return null;
};
const writeSave = (data) => {
  try { localStorage.setItem(LS_KEY, JSON.stringify(data)); } catch (e) { console.warn("Failed to save:", e); }
};

// ═══ MAIN APP ═══
export default function App(){
  const saved = useMemo(() => loadSave(), []);
  const[xp,setXp]=useState(saved?.xp || 0);
  const[streak,setStreak]=useState(saved?.streak || 1);
  const[lastStudy,setLastStudy]=useState(saved?.lastStudy || null);
  const[done,setDone]=useState(saved?.done || {});
  const[tasks,setTasks]=useState(saved?.tasks || {});
  const[confMap,setConfMap]=useState(saved?.confMap || {});
  const[quizHistory,setQuizHistory]=useState(saved?.quizHistory || []);
  const[xpLog,setXpLog]=useState(saved?.xpLog || {}); // tracks one-time XP grants
  const[view,setView]=useState("home");
  const[adom,setAdom]=useState(null);
  const[aobj,setAobj]=useState(null);
  const[atop,setAtop]=useState(null);
  const[quiz,setQuiz]=useState(null);
  const[pbq,setPbq]=useState(null);
  const[toast,setToast]=useState(null);
  const[lvl,setLvl]=useState(null);
  const[flashDeck,setFlashDeck]=useState(null);
  const[flashIdx,setFlashIdx]=useState(0);
  const[flashFlipped,setFlashFlipped]=useState(false);
  const[flashScore,setFlashScore]=useState({right:0,wrong:0});
  const[expanded,setExpanded]=useState({}); // collapsible sections

  // ═══ AUTO-SAVE ═══
  useEffect(() => {
    const today = new Date().toDateString();
    if (lastStudy && lastStudy !== today) {
      const last = new Date(lastStudy);
      const diff = Math.floor((new Date(today) - last) / 86400000);
      if (diff > 1) setStreak(1);
    }
    writeSave({ xp, streak, lastStudy: today, done, tasks, confMap, quizHistory, xpLog, version: 2 });
    setLastStudy(today);
  }, [xp, done, tasks, confMap, quizHistory, xpLog]);

  const rank=getRank(xp);const total=allTopics().length;
  const doneN=Object.keys(done).length;const pct=total?Math.round(doneN/total*100):0;
  const domPct=(d)=>{const t=d.objectives.flatMap(o=>o.topics);const dn=t.filter(x=>done[x.id]).length;return t.length?Math.round(dn/t.length*100):0;};

  const giveXp=useCallback((a,l)=>{
    const old=getRank(xp);setXp(p=>p+a);setToast({a,l});setTimeout(()=>setToast(null),2200);
    const nw=getRank(xp+a);if(nw.lv>old.lv)setTimeout(()=>{setLvl(nw);setTimeout(()=>setLvl(null),4000);},600);
  },[xp]);

  // ═══ XP EXPLOIT FIX — one-time grants only ═══
  const markDone=(id)=>{
    if(!done[id]){
      setDone(p=>({...p,[id]:1}));
      if(!xpLog[`topic-${id}`]){
        giveXp(XP.topic,"Topic mastered");
        setXpLog(p=>({...p,[`topic-${id}`]:1}));
      }
    }
  };
  const togTask=(k)=>{
    if(!tasks[k]){
      setTasks(p=>({...p,[k]:1}));
      if(!xpLog[`task-${k}`]){
        giveXp(XP.task,"Mission done");
        setXpLog(p=>({...p,[`task-${k}`]:1}));
      }
    } else {
      setTasks(p=>{const n={...p};delete n[k];return n;});
    }
  };

  const toggleSection=(key)=>setExpanded(p=>({...p,[key]:!p[key]}));

  const startQuiz=(qs,mode="practice")=>{
    const q=mode==="shadow"?qs.map(shadowQ):qs;
    setQuiz({qs:q,ans:{},conf:{},sub:false,correct:0,total:q.length,mode});setView("quiz");
  };
  const submitQuiz=()=>{
    if(!quiz)return;let c=0;quiz.qs.forEach((q,i)=>{if(quiz.ans[i]===q.a)c++;});
    const earned=c*XP.quiz+(c===quiz.total?XP.perfect:0)+(quiz.mode==="shadow"?XP.shadow:0);
    giveXp(earned,quiz.mode==="shadow"?`Shadow: ${Math.round(c/quiz.total*100)}%`:`${c}/${quiz.total}`);
    setQuiz(p=>({...p,sub:true,correct:c}));
    setQuizHistory(h=>[...h,{date:new Date().toISOString(),mode:quiz.mode,correct:c,total:quiz.total,pct:Math.round(c/quiz.total*100)}]);
  };
  const startShadow=()=>{
    const w=[];DB.domains.forEach(d=>{const qs=d.objectives.flatMap(o=>o.questions||[]);const cnt=Math.round(d.weight/100*40);const sh=[...qs].sort(()=>Math.random()-.5);w.push(...sh.slice(0,cnt));});
    startQuiz(w.sort(()=>Math.random()-.5).slice(0,40),"shadow");
  };

  // ═══ MODERN LIGHT THEME ═══
  const C={
    bg:"#f8f9fc",     // light background
    cd:"#ffffff",     // card
    bd:"#e2e6ef",     // border
    ac:"#4361ee",     // primary accent (blue)
    ac2:"#7209b7",    // secondary accent (purple)
    acG:"#06d6a0",    // green/success
    tx:"#1a1a2e",     // text
    mt:"#6b7280",     // muted text
    br:"#0f0f23",     // bright/heading text
    dn:"#ef4444",     // danger
    warn:"#f59e0b",   // warning/orange
    shadow:"0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)",
    shadowHov:"0 4px 12px rgba(67,97,238,0.15)",
  };

  const nav=(v)=>{setView(v);setAdom(null);setAobj(null);setAtop(null);setQuiz(null);setPbq(null);};

  // ═══ COLLAPSIBLE SECTION COMPONENT ═══
  const Section=({title,icon,color,id,children,defaultOpen})=>{
    const isOpen = expanded[id] !== undefined ? expanded[id] : (defaultOpen || false);
    return(
      <div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,marginBottom:12,boxShadow:C.shadow,overflow:"hidden"}}>
        <button onClick={()=>toggleSection(id)} style={{width:"100%",padding:"14px 18px",display:"flex",alignItems:"center",gap:10,background:"none",border:"none",textAlign:"left",cursor:"pointer"}}>
          <span style={{fontSize:16}}>{icon}</span>
          <span style={{fontFamily:"'Inter',sans-serif",fontSize:13,fontWeight:600,color:color||C.br,flex:1}}>{title}</span>
          <span style={{fontSize:18,color:C.mt,transition:"transform .2s",transform:isOpen?"rotate(180deg)":"rotate(0)"}}>{isOpen?"▾":"▸"}</span>
        </button>
        {isOpen&&<div style={{padding:"0 18px 16px",animation:"fadeUp .2s"}}>{children}</div>}
      </div>
    );
  };

  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.tx,fontFamily:"'Inter','Segoe UI',system-ui,sans-serif"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:${C.bg}}::-webkit-scrollbar-thumb{background:${C.bd};border-radius:3px}
        @keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes xpPop{0%{opacity:1;transform:translateY(0) scale(1)}50%{transform:translateY(-20px) scale(1.1)}100%{opacity:0;transform:translateY(-50px) scale(0.9)}}
        @keyframes glow{0%,100%{box-shadow:0 0 30px ${C.ac}22}50%{box-shadow:0 0 60px ${C.ac}44}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
        @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
        button{font-family:inherit;cursor:pointer;transition:all .15s ease}
        .card:hover{box-shadow:${C.shadowHov};transform:translateY(-2px);border-color:${C.ac}33!important}
      `}</style>

      {/* XP Toast */}
      {toast&&<div style={{position:"fixed",top:80,right:20,zIndex:1001,animation:"xpPop 2.2s forwards",fontFamily:"'Inter'",fontSize:20,fontWeight:800,color:C.ac,background:C.cd,padding:"10px 18px",borderRadius:12,boxShadow:"0 8px 30px rgba(67,97,238,0.3)",border:`2px solid ${C.ac}33`}}>+{toast.a} XP <span style={{fontSize:11,opacity:.6,fontWeight:500}}>{toast.l}</span></div>}

      {/* Level Up Modal */}
      {lvl&&<div style={{position:"fixed",inset:0,zIndex:1002,display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,0,0,0.5)",backdropFilter:"blur(8px)"}}>
        <div style={{animation:"glow 1.5s infinite",textAlign:"center",padding:48,background:C.cd,border:`2px solid ${C.ac}`,borderRadius:20,boxShadow:"0 20px 60px rgba(67,97,238,0.3)"}}>
          <div style={{fontSize:64,marginBottom:12}}>{lvl.b}</div>
          <div style={{fontSize:12,letterSpacing:5,color:C.ac,fontWeight:700,textTransform:"uppercase"}}>Level Up!</div>
          <div style={{fontSize:28,fontWeight:800,color:C.br,marginTop:8}}>Level {lvl.lv}: {lvl.t}</div>
        </div>
      </div>}

      {/* ═══ HEADER ═══ */}
      <header style={{background:C.cd,borderBottom:`1px solid ${C.bd}`,padding:"12px 20px",position:"sticky",top:0,zIndex:100,boxShadow:"0 1px 4px rgba(0,0,0,0.04)"}}>
        <div style={{maxWidth:960,margin:"0 auto",display:"flex",alignItems:"center",gap:14}}>
          {/* Rank Circle */}
          <div style={{width:44,height:44,borderRadius:"50%",background:`conic-gradient(${C.ac} ${rank.p*3.6}deg, ${C.bd} ${rank.p*3.6}deg)`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
            <div style={{width:36,height:36,borderRadius:"50%",background:C.cd,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>{rank.b}</div>
          </div>
          {/* Level + XP bar */}
          <div style={{flex:1}}>
            <div style={{display:"flex",alignItems:"baseline",gap:8}}>
              <span style={{fontSize:12,fontWeight:700,color:C.ac}}>LVL {rank.lv}</span>
              <span style={{fontSize:12,color:C.mt,fontWeight:500}}>{rank.t}</span>
              <span style={{fontSize:11,color:C.mt,marginLeft:"auto"}}>{xp.toLocaleString()}{rank.n?` / ${rank.n.xp.toLocaleString()}`:""} XP</span>
            </div>
            <div style={{height:5,background:C.bd,borderRadius:4,marginTop:5}}>
              <div style={{height:"100%",width:`${rank.p}%`,background:`linear-gradient(90deg,${C.ac},${C.ac2})`,borderRadius:4,transition:"width .5s"}}/>
            </div>
          </div>
          {/* Progress + Streak */}
          <div style={{textAlign:"center",padding:"0 8px"}}><div style={{fontSize:20,fontWeight:800,color:C.br}}>{pct}%</div><div style={{fontSize:10,color:C.mt,fontWeight:500}}>Done</div></div>
          <div style={{textAlign:"center",padding:"0 8px"}}><div style={{fontSize:18,fontWeight:700,color:C.warn}}>{streak>1?"🔥 ":""}{streak}d</div><div style={{fontSize:10,color:C.mt,fontWeight:500}}>Streak</div></div>
        </div>
      </header>

      {/* ═══ NAV ═══ */}
      <nav style={{background:C.cd,borderBottom:`1px solid ${C.bd}`,padding:"0 20px"}}>
        <div style={{maxWidth:960,margin:"0 auto",display:"flex",gap:0}}>
          {[{k:"home",l:"🏠 Home"},{k:"study",l:"📖 Study"},{k:"flash",l:"🃏 Flashcards"},{k:"missions",l:"⚡ Missions"},{k:"pbq",l:"🖥️ PBQ Lab"},{k:"exam",l:"🎯 Shadow"}].map(n=>(
            <button key={n.k} onClick={()=>nav(n.k)} style={{padding:"12px 16px",fontSize:13,fontWeight:view===n.k?600:500,whiteSpace:"nowrap",background:"transparent",color:view===n.k?C.ac:C.mt,border:"none",borderBottom:view===n.k?`3px solid ${C.ac}`:"3px solid transparent",transition:"all .15s"}}>{n.l}</button>
          ))}
        </div>
      </nav>

      <main style={{maxWidth:960,margin:"0 auto",padding:20}}>

      {/* ══════ HOME ══════ */}
      {view==="home"&&(<div style={{animation:"fadeUp .4s"}}>
        {/* Hero */}
        <div style={{background:`linear-gradient(135deg,${C.ac},${C.ac2})`,borderRadius:18,padding:32,marginBottom:20,color:"#fff",boxShadow:"0 8px 32px rgba(67,97,238,0.25)"}}>
          <div style={{fontSize:11,letterSpacing:3,fontWeight:600,opacity:.85,textTransform:"uppercase",animation:"pulse 3s infinite"}}>◉ Active Session</div>
          <h1 style={{fontSize:26,fontWeight:800,marginTop:6}}>Security+ SY0-701</h1>
          <p style={{fontSize:14,marginTop:8,lineHeight:1.6,maxWidth:550,opacity:.9}}>
            {total} topics · {allQuestions().length} questions · PBQ simulator · Shadow exam mode. Study from zero to certification-ready.
          </p>
          {/* Stats Row */}
          <div style={{display:"flex",gap:10,marginTop:18,flexWrap:"wrap"}}>
            {[{v:`${doneN}/${total}`,l:"Topics",bg:"rgba(255,255,255,0.2)"},{v:allQuestions().length,l:"Questions",bg:"rgba(255,255,255,0.15)"},{v:Object.keys(tasks).length,l:"Missions",bg:"rgba(255,255,255,0.15)"},{v:xp.toLocaleString(),l:"Total XP",bg:"rgba(255,255,255,0.15)"}].map((s,i)=>(
              <div key={i} style={{background:s.bg,borderRadius:10,padding:"10px 18px",textAlign:"center",backdropFilter:"blur(10px)"}}>
                <div style={{fontSize:20,fontWeight:800}}>{s.v}</div>
                <div style={{fontSize:10,fontWeight:500,opacity:.8}}>{s.l}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Domain Cards */}
        <div style={{fontSize:12,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:10}}>Domains — Priority Order</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
          {[...DB.domains].sort((a,b)=>b.weight-a.weight).map(d=>{const dp=domPct(d);return(
            <button key={d.id} className="card" onClick={()=>{setView("study");setAdom(d)}} style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:18,textAlign:"left",borderLeft:`4px solid ${d.color}`,position:"relative",boxShadow:C.shadow}}>
              {d.weight>=22&&<div style={{position:"absolute",top:8,right:10,fontSize:10,fontWeight:700,color:"#fff",background:d.color,padding:"3px 8px",borderRadius:6}}>HIGH</div>}
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:28}}>{d.icon}</span><span style={{fontSize:22,fontWeight:800,color:d.color}}>{dp}%</span></div>
              <div style={{fontSize:13,fontWeight:600,color:C.br,marginTop:8}}>{d.title}</div>
              <div style={{fontSize:11,color:C.mt,marginTop:3}}>{d.weight}% of exam · {d.objectives.flatMap(o=>o.topics).length} topics</div>
              <div style={{height:5,background:C.bd,borderRadius:4,marginTop:10}}><div style={{height:"100%",width:`${dp}%`,background:d.color,borderRadius:4,transition:"width .3s"}}/></div>
            </button>
          );})}
        </div>

        {/* Quick Actions */}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:16}}>
          <button onClick={()=>{const q=allQuestions().sort(()=>Math.random()-.5).slice(0,10);startQuiz(q);}} style={{padding:16,borderRadius:12,background:C.cd,border:`1px solid ${C.bd}`,boxShadow:C.shadow,color:C.ac,fontSize:13,fontWeight:600}}>🧠 Quick 10</button>
          <button onClick={()=>nav("pbq")} style={{padding:16,borderRadius:12,background:C.cd,border:`1px solid ${C.bd}`,boxShadow:C.shadow,color:C.ac2,fontSize:13,fontWeight:600}}>🖥️ PBQ Lab</button>
          <button onClick={startShadow} style={{padding:16,borderRadius:12,background:C.cd,border:`1px solid ${C.bd}`,boxShadow:C.shadow,color:C.dn,fontSize:13,fontWeight:600}}>🎯 Shadow</button>
        </div>

        {/* Quiz History */}
        {quizHistory.length>0&&<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:16,marginBottom:12,boxShadow:C.shadow}}>
          <div style={{fontSize:12,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:10}}>Recent Scores</div>
          <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
            {quizHistory.slice(-12).map((h,i)=><div key={i} style={{padding:"6px 12px",borderRadius:8,fontSize:12,fontWeight:600,background:h.pct>=83?"#ecfdf5":h.pct>=60?"#fffbeb":"#fef2f2",border:`1px solid ${h.pct>=83?"#a7f3d0":h.pct>=60?"#fde68a":"#fecaca"}`,color:h.pct>=83?"#065f46":h.pct>=60?"#92400e":"#991b1b"}}>{h.pct}% <span style={{fontWeight:400,opacity:.7}}>{h.mode}</span></div>)}
          </div>
        </div>}

        
        {/* Weak Areas Dashboard */}
        {quizHistory.length>=3&&<div style={{background:C.cd,border:"1px solid "+C.bd,borderRadius:14,padding:16,marginBottom:12,boxShadow:C.shadow}}>
          <div style={{fontSize:12,fontWeight:600,color:C.dn,letterSpacing:1,textTransform:"uppercase",marginBottom:10}}>Focus Areas</div>
          {(()=>{
            const recent=quizHistory.slice(-20);
            const total=recent.reduce((a,h)=>a+h.total,0);
            const correct=recent.reduce((a,h)=>a+h.correct,0);
            const avgPct=total>0?Math.round(correct/total*100):0;
            const domScores=DB.domains.map(d=>{
              const dq=d.objectives.flatMap(o=>o.questions||[]);
              return{id:d.id,title:d.title,icon:d.icon,color:d.color,weight:d.weight,qCount:dq.length,pct:domPct(d)};
            });
            const weakest=domScores.filter(d=>d.pct<50).sort((a,b)=>b.weight-a.weight);
            return(<div>
              <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}>
                <div style={{fontSize:14,fontWeight:700,color:avgPct>=83?C.acG:avgPct>=60?C.warn:C.dn}}>{avgPct}%</div>
                <div style={{fontSize:12,color:C.mt}}>avg across last {recent.length} quizzes {avgPct>=83?"- Passing range!":avgPct>=60?"- Getting close":"- Needs work"}</div>
              </div>
              {weakest.length>0?weakest.map(d=>(
                <div key={d.id} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 0",borderBottom:"1px solid "+C.bd}}>
                  <span style={{fontSize:16}}>{d.icon}</span>
                  <div style={{flex:1}}>
                    <div style={{fontSize:12,fontWeight:600,color:C.br}}>Domain {d.id}: {d.title}</div>
                    <div style={{fontSize:11,color:C.mt}}>{d.weight}% of exam - only {d.pct}% complete</div>
                  </div>
                  <button onClick={()=>{setView("study");setAdom(DB.domains.find(x=>x.id===d.id))}} style={{padding:"4px 12px",borderRadius:6,fontSize:11,fontWeight:600,background:d.color+"15",border:"1px solid "+d.color+"33",color:d.color}}>Study</button>
                </div>
              )):<div style={{fontSize:12,color:C.acG}}>All domains above 50% - keep pushing to 100%!</div>}
            </div>);
          })()}
        </div>}

        {/* Save Info + Reset */}
        <div style={{display:"flex",gap:10,alignItems:"center",padding:"8px 0"}}>
          <div style={{fontSize:11,color:C.mt,flex:1}}>💾 Progress auto-saves. {lastStudy&&`Last session: ${lastStudy}`}</div>
          <button onClick={()=>{if(window.confirm("⚠️ Reset ALL progress? This cannot be undone.")){localStorage.removeItem(LS_KEY);window.location.reload();}}} style={{padding:"6px 14px",borderRadius:8,fontSize:11,background:"#fef2f2",border:"1px solid #fecaca",color:"#991b1b",fontWeight:500}}>Reset Progress</button>
        </div>
      </div>)}

      {/* ══════ STUDY ══════ */}
      {view==="study"&&!atop&&!quiz&&(<div style={{animation:"fadeUp .3s"}}>
        {!adom?(<>
          <div style={{fontSize:12,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:12}}>All Domains</div>
          {DB.domains.map(d=><button key={d.id} className="card" onClick={()=>setAdom(d)} style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:12,padding:16,marginBottom:8,textAlign:"left",display:"flex",alignItems:"center",gap:14,borderLeft:`4px solid ${d.color}`,boxShadow:C.shadow}}>
            <span style={{fontSize:30}}>{d.icon}</span>
            <div style={{flex:1}}>
              <div style={{fontSize:14,fontWeight:600,color:C.br}}>Domain {d.id}: {d.title}</div>
              <div style={{fontSize:12,color:C.mt,marginTop:3}}>{d.weight}% · {d.objectives.length} objectives · {d.objectives.flatMap(o=>o.topics).length} topics</div>
              <div style={{height:5,background:C.bd,borderRadius:4,marginTop:8}}><div style={{height:"100%",width:`${domPct(d)}%`,background:d.color,borderRadius:4}}/></div>
            </div>
            <span style={{fontSize:22,fontWeight:800,color:d.color}}>{domPct(d)}%</span>
          </button>)}
        </>):!aobj?(<>
          <button onClick={()=>setAdom(null)} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500,marginBottom:12}}>← All Domains</button>
          <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
            <span style={{fontSize:36}}>{adom.icon}</span>
            <div><div style={{fontSize:18,fontWeight:700,color:C.br}}>Domain {adom.id}: {adom.title}</div><div style={{fontSize:13,color:C.mt,marginTop:2}}>{adom.weight}% of exam · {domPct(adom)}% complete</div></div>
          </div>
          {adom.objectives.map(obj=>{const objTopics=obj.topics;const objDone=objTopics.filter(t=>done[t.id]).length;return(
            <button key={obj.id} className="card" onClick={()=>setAobj(obj)} style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:12,padding:16,marginBottom:8,textAlign:"left",display:"flex",alignItems:"center",gap:12,boxShadow:C.shadow}}>
              <div style={{width:40,height:40,borderRadius:10,background:`${adom.color}15`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:700,color:adom.color,flexShrink:0}}>{obj.id}</div>
              <div style={{flex:1}}>
                <div style={{fontSize:13,fontWeight:600,color:C.br}}>{obj.title}</div>
                <div style={{fontSize:11,color:C.mt,marginTop:3}}>{objTopics.length} topics · {(obj.questions||[]).length} questions · {objDone}/{objTopics.length} done</div>
              </div>
              <span style={{color:C.mt,fontSize:16}}>›</span>
            </button>
          );})}
          <button onClick={()=>{const q=adom.objectives.flatMap(o=>o.questions||[]).sort(()=>Math.random()-.5);if(q.length)startQuiz(q);}} style={{width:"100%",padding:14,marginTop:10,borderRadius:12,background:C.ac,color:"#fff",border:"none",fontSize:14,fontWeight:600,boxShadow:"0 4px 14px rgba(67,97,238,0.3)"}}>🧠 Domain {adom.id} Quiz ({adom.objectives.flatMap(o=>o.questions||[]).length} questions)</button>
        </>):(<>
          <button onClick={()=>setAobj(null)} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500,marginBottom:12}}>← {adom.title}</button>
          <div style={{fontSize:11,fontWeight:600,letterSpacing:1,color:adom.color,textTransform:"uppercase",marginBottom:12}}>{aobj.id} — {aobj.title}</div>
          {aobj.topics.map(topic=>{const isDone=done[topic.id];return(
            <button key={topic.id} className="card" onClick={()=>setAtop(topic)} style={{width:"100%",background:isDone?"#f0fdf4":C.cd,border:`1px solid ${isDone?"#bbf7d0":C.bd}`,borderRadius:12,padding:14,marginBottom:6,textAlign:"left",display:"flex",alignItems:"center",gap:12,boxShadow:C.shadow}}>
              <div style={{width:26,height:26,borderRadius:"50%",background:isDone?"#06d6a0":"#f3f4f6",border:`2px solid ${isDone?"#06d6a0":"#d1d5db"}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,color:"#fff",flexShrink:0}}>{isDone?"✓":""}</div>
              <div style={{flex:1}}>
                <div style={{fontSize:13,fontWeight:isDone?600:500,color:isDone?"#065f46":C.br}}>{topic.title}</div>
                <div style={{fontSize:11,color:C.mt,marginTop:2}}>{topic.terms?.length||0} key terms · {topic.tasks?.length||0} missions</div>
              </div>
              <span style={{color:C.mt,fontSize:16}}>›</span>
            </button>
          );})}
          {(aobj.questions||[]).length>0&&<button onClick={()=>startQuiz(aobj.questions||[])} style={{width:"100%",padding:14,marginTop:8,borderRadius:12,background:`${adom.color}10`,border:`2px solid ${adom.color}44`,color:adom.color,fontSize:14,fontWeight:600}}>🧠 Quiz: {aobj.id} ({(aobj.questions||[]).length} questions)</button>}
        </>)}
      </div>)}

      {/* ══════ TOPIC DETAIL — COLLAPSIBLE SECTIONS ══════ */}
      {view==="study"&&atop&&!quiz&&(<div style={{animation:"fadeUp .3s"}}>
        <button onClick={()=>setAtop(null)} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500,marginBottom:12}}>← Back</button>

        {/* Topic Header */}
        <div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:20,marginBottom:12,display:"flex",justifyContent:"space-between",alignItems:"center",boxShadow:C.shadow}}>
          <h2 style={{fontSize:18,fontWeight:700,color:C.br}}>{atop.title}</h2>
          <button onClick={()=>markDone(atop.id)} style={{padding:"8px 18px",borderRadius:10,fontSize:12,fontWeight:600,background:done[atop.id]?"#ecfdf5":C.ac,color:done[atop.id]?"#065f46":"#fff",border:done[atop.id]?"1px solid #a7f3d0":"none",boxShadow:done[atop.id]?"none":"0 4px 12px rgba(67,97,238,0.25)"}}>{done[atop.id]?"✓ Completed":"Complete +60 XP"}</button>
        </div>

        {/* Plain English — open by default */}
        <Section title="Plain English Explanation" icon="💡" color={C.warn} id={`plain-${atop.id}`} defaultOpen={true}>
          <p style={{fontSize:14,color:C.tx,lineHeight:1.9}}>{atop.plain}</p>
        </Section>

        {/* Exam Tip */}
        {atop.examTip&&<Section title="Exam Tip - How CompTIA Tests This" icon="\u26a0\ufe0f" color={C.dn} id={"tip-"+atop.id} defaultOpen={true}>
          <div style={{padding:"12px 16px",background:"#fef2f2",borderRadius:10,border:"1px solid #fecaca"}}>
            <p style={{fontSize:14,color:"#991b1b",lineHeight:1.8,fontWeight:500}}>{atop.examTip}</p>
          </div>
        </Section>}


        {/* Technical — collapsed by default */}
        <Section title="Technical Documentation" icon="📐" color={C.ac} id={`tech-${atop.id}`}>
          <p style={{fontSize:13,color:C.tx,lineHeight:1.9}}>{atop.tech}</p>
          {atop.terms&&<div style={{marginTop:14}}>
            <div style={{fontSize:11,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:8}}>Key Terms</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>{atop.terms.map((t,i)=><span key={i} style={{padding:"5px 12px",borderRadius:8,fontSize:12,background:"#f1f5f9",border:"1px solid #e2e8f0",color:"#475569",fontWeight:500}}>{t}</span>)}</div>
          </div>}
        </Section>

        {/* Missions — collapsed */}
        {atop.tasks&&<Section title={`Study Missions (${atop.tasks.length})`} icon="⚡" color={C.warn} id={`tasks-${atop.id}`}>
          {atop.tasks.map((task,i)=>{const k=`${atop.id}-${i}`;const d2=tasks[k];return(
            <button key={i} onClick={()=>togTask(k)} style={{width:"100%",display:"flex",alignItems:"start",gap:10,padding:"10px 0",borderBottom:i<atop.tasks.length-1?`1px solid ${C.bd}`:"none",background:"none",border:"none",textAlign:"left"}}>
              <div style={{width:20,height:20,borderRadius:6,flexShrink:0,marginTop:1,background:d2?C.warn:"#f3f4f6",border:`2px solid ${d2?C.warn:"#d1d5db"}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,color:"#fff"}}>{d2?"✓":""}</div>
              <div>
                <div style={{fontSize:13,color:d2?"#92400e":C.tx,textDecoration:d2?"line-through":"none",opacity:d2?.6:1,lineHeight:1.5}}>{task}</div>
                {!d2&&!xpLog[`task-${k}`]&&<div style={{fontSize:11,color:C.acG,marginTop:2,fontWeight:500}}>+45 XP</div>}
              </div>
            </button>
          );})}
        </Section>}
      </div>)}

      {/* ══════ QUIZ ══════ */}
      {view==="quiz"&&quiz&&(<div style={{animation:"fadeUp .3s"}}>
        <button onClick={()=>{setQuiz(null);setView("study")}} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500,marginBottom:12}}>← Exit Quiz</button>
        <div style={{fontSize:16,fontWeight:700,color:C.br,marginBottom:6}}>
          {quiz.mode==="shadow"?"🎯 Shadow Exam":"🧠 Knowledge Check"} — {quiz.total} Questions
        </div>
        {quiz.mode==="shadow"&&<div style={{fontSize:12,color:C.dn,marginBottom:14,padding:"8px 14px",background:"#fef2f2",borderRadius:8,border:"1px solid #fecaca"}}>⚠️ Shadow mode uses harder wording than the real exam.</div>}

        {quiz.qs.map((q,qi)=>{const sel=quiz.ans[qi];const ok=quiz.sub&&sel===q.a;const wrong=quiz.sub&&sel!==undefined&&sel!==q.a;return(
          <div key={qi} style={{background:C.cd,border:`1px solid ${ok?"#a7f3d0":wrong?"#fecaca":C.bd}`,borderRadius:14,padding:18,marginBottom:10,boxShadow:C.shadow}}>
            <div style={{fontSize:14,fontWeight:600,color:C.br,marginBottom:10,lineHeight:1.5}}>Q{qi+1}. {q.q}</div>
            <div style={{display:"grid",gap:6}}>
              {q.o.map((opt,oi)=>{const isSel=sel===oi;const isAns=quiz.sub&&oi===q.a;
                let bg="#f8f9fc",bc=C.bd,tc=C.tx;
                if(quiz.sub){if(isAns){bg="#ecfdf5";bc="#06d6a0";tc="#065f46";}else if(isSel){bg="#fef2f2";bc="#ef4444";tc="#991b1b";}}
                else if(isSel){bg="#eff6ff";bc=C.ac;tc=C.ac;}
                return(<button key={oi} disabled={quiz.sub} onClick={()=>setQuiz(p=>({...p,ans:{...p.ans,[qi]:oi}}))} style={{padding:"10px 14px",borderRadius:10,textAlign:"left",background:bg,border:`2px solid ${bc}`,color:tc,fontSize:13,fontWeight:isSel||isAns?600:400,opacity:quiz.sub&&!isAns&&!isSel?.4:1}}>
                  <b style={{marginRight:8,color:C.mt}}>{String.fromCharCode(65+oi)}.</b>{opt}{quiz.sub&&isAns?" ✓":""}
                </button>);
              })}
            </div>
            {quiz.sub&&q.x&&<div style={{marginTop:10,padding:"10px 14px",background:ok?"#ecfdf5":"#eff6ff",borderRadius:10,fontSize:12,color:ok?"#065f46":"#1e40af",lineHeight:1.6,borderLeft:`4px solid ${ok?"#06d6a0":C.ac}`}}>💡 {q.x}</div>}
            {quiz.sub&&<div style={{marginTop:8,display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontSize:11,color:C.mt,fontWeight:500}}>Confidence:</span>
              {[1,2,3,4,5].map(c=><button key={c} onClick={()=>setQuiz(p=>({...p,conf:{...p.conf,[qi]:c}}))} style={{width:28,height:28,borderRadius:8,border:`2px solid ${quiz.conf[qi]>=c?C.ac:C.bd}`,background:quiz.conf[qi]>=c?`${C.ac}15`:"transparent",color:quiz.conf[qi]>=c?C.ac:C.mt,fontSize:12,fontWeight:600,display:"flex",alignItems:"center",justifyContent:"center"}}>{c}</button>)}
            </div>}
          </div>
        );})}

        {!quiz.sub?<button onClick={submitQuiz} disabled={Object.keys(quiz.ans).length<quiz.total} style={{width:"100%",padding:16,borderRadius:12,background:Object.keys(quiz.ans).length<quiz.total?"#e5e7eb":C.ac,color:Object.keys(quiz.ans).length<quiz.total?C.mt:"#fff",border:"none",fontSize:14,fontWeight:700,boxShadow:Object.keys(quiz.ans).length>=quiz.total?"0 4px 14px rgba(67,97,238,0.3)":"none"}}>SUBMIT ANSWERS</button>
        :<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:24,textAlign:"center",boxShadow:C.shadow}}>
          <div style={{fontSize:36,fontWeight:800,color:quiz.correct===quiz.total?C.acG:quiz.correct/quiz.total>=.75?C.ac:C.dn}}>{Math.round(quiz.correct/quiz.total*100)}%</div>
          <div style={{fontSize:14,color:C.mt,marginTop:4}}>{quiz.correct}/{quiz.total} correct{quiz.correct===quiz.total?" — PERFECT! 🎉":quiz.correct/quiz.total>=.83?" — Passing score!":quiz.correct/quiz.total>=.5?" — Keep studying.":" — Review this material."}</div>
          <div style={{fontSize:11,color:C.mt,marginTop:6}}>Rate your confidence (1-5) on each question above.</div>
          <button onClick={()=>{setQuiz(null);setView("study")}} style={{marginTop:14,padding:"10px 28px",borderRadius:10,fontSize:13,fontWeight:600,background:"#f3f4f6",border:`1px solid ${C.bd}`,color:C.mt}}>Done</button>
        </div>}
      </div>)}

      {/* ══════ FLASHCARDS ══════ */}
      {view==="flash"&&(<div style={{animation:"fadeUp .3s"}}>
        {!flashDeck?(<div>
          <div style={{fontSize:12,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:14}}>🃏 Flashcard Decks</div>
          <button onClick={()=>{const cards=allTopics().filter(t=>t.terms).flatMap(t=>t.terms.map(term=>({front:term,back:t.title}))).sort(()=>Math.random()-.5).slice(0,30);setFlashDeck(cards);setFlashIdx(0);setFlashFlipped(false);setFlashScore({right:0,wrong:0});}} className="card" style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:20,marginBottom:10,textAlign:"left",boxShadow:C.shadow}}>
            <div style={{fontSize:16,fontWeight:700,color:C.br}}>🔤 Key Terms — Random 30</div>
            <div style={{fontSize:12,color:C.mt,marginTop:4}}>See the term, recall which topic it belongs to and what it means</div>
          </button>
          {DB.domains.map(d=>{
            const cards=d.objectives.flatMap(o=>o.topics.filter(t=>t.terms).flatMap(t=>t.terms.map(term=>({front:term,back:t.title+" — "+t.plain.slice(0,120)+"..."}))));
            return cards.length>0&&<button key={d.id} onClick={()=>{setFlashDeck(cards.sort(()=>Math.random()-.5));setFlashIdx(0);setFlashFlipped(false);setFlashScore({right:0,wrong:0});}} className="card" style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:16,marginBottom:8,textAlign:"left",boxShadow:C.shadow,borderLeft:`4px solid ${d.color}`}}>
              <div style={{fontSize:14,fontWeight:600,color:C.br}}>{d.icon} Domain {d.id}: {d.title}</div>
              <div style={{fontSize:11,color:C.mt,marginTop:3}}>{cards.length} terms</div>
            </button>
          })}
          <button onClick={()=>{const cards=allQuestions().sort(()=>Math.random()-.5).slice(0,25).map(q=>({front:q.q,back:"Answer: "+q.o[q.a]+"\n\n"+q.x}));setFlashDeck(cards);setFlashIdx(0);setFlashFlipped(false);setFlashScore({right:0,wrong:0});}} className="card" style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:16,marginBottom:8,textAlign:"left",boxShadow:C.shadow,borderLeft:`4px solid ${C.dn}`}}>
            <div style={{fontSize:14,fontWeight:600,color:C.br}}>❓ Question Recall — Random 25</div>
            <div style={{fontSize:11,color:C.mt,marginTop:3}}>See the question, recall the answer before flipping</div>
          </button>
        </div>)
        :flashIdx >= flashDeck.length?(<div style={{textAlign:"center",padding:40}}>
          <div style={{fontSize:48,marginBottom:16}}>{Math.round(flashScore.right/flashDeck.length*100)>=80?"🎉":Math.round(flashScore.right/flashDeck.length*100)>=60?"👍":"📚"}</div>
          <div style={{fontSize:24,fontWeight:800,color:Math.round(flashScore.right/flashDeck.length*100)>=80?C.acG:Math.round(flashScore.right/flashDeck.length*100)>=60?C.ac:C.dn}}>{Math.round(flashScore.right/flashDeck.length*100)}%</div>
          <div style={{fontSize:14,color:C.mt,marginTop:6}}>Knew: {flashScore.right} / {flashDeck.length}</div>
          <div style={{display:"flex",gap:10,justifyContent:"center",marginTop:20}}>
            <button onClick={()=>{setFlashIdx(0);setFlashFlipped(false);setFlashScore({right:0,wrong:0});setFlashDeck([...flashDeck].sort(()=>Math.random()-.5));}} style={{padding:"10px 24px",borderRadius:10,background:C.ac,color:"#fff",border:"none",fontSize:13,fontWeight:600}}>Retry Deck</button>
            <button onClick={()=>setFlashDeck(null)} style={{padding:"10px 24px",borderRadius:10,background:"#f3f4f6",border:`1px solid ${C.bd}`,color:C.mt,fontSize:13,fontWeight:600}}>All Decks</button>
          </div>
        </div>)
        :(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
            <button onClick={()=>{setFlashDeck(null);setFlashIdx(0);setFlashFlipped(false);}} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500}}>← Decks</button>
            <span style={{fontSize:12,color:C.mt}}>{flashIdx+1} / {flashDeck.length} · ✅ {flashScore.right} · ❌ {flashScore.wrong}</span>
          </div>
          <div onClick={()=>setFlashFlipped(!flashFlipped)} style={{background:flashFlipped?"linear-gradient(135deg,#ecfdf5,#f0fdf4)":C.cd,border:`2px solid ${flashFlipped?C.acG:C.bd}`,borderRadius:18,padding:40,minHeight:220,display:"flex",alignItems:"center",justifyContent:"center",textAlign:"center",cursor:"pointer",boxShadow:"0 8px 30px rgba(0,0,0,0.08)",transition:"all .3s"}}>
            <div>
              <div style={{fontSize:10,fontWeight:600,letterSpacing:2,color:C.mt,textTransform:"uppercase",marginBottom:14}}>{flashFlipped?"Answer":"Term / Question"}</div>
              <div style={{fontSize:flashFlipped?15:20,fontWeight:flashFlipped?500:700,color:C.br,lineHeight:1.6,maxWidth:500,whiteSpace:"pre-wrap"}}>{flashFlipped?flashDeck[flashIdx].back:flashDeck[flashIdx].front}</div>
              {!flashFlipped&&<div style={{fontSize:11,color:C.mt,marginTop:16}}>Tap to reveal answer</div>}
            </div>
          </div>
          {flashFlipped&&<div style={{display:"flex",gap:10,justifyContent:"center",marginTop:16}}>
            <button onClick={()=>{setFlashScore(s=>({...s,right:s.right+1}));setFlashIdx(flashIdx+1);setFlashFlipped(false);}} style={{padding:"12px 32px",borderRadius:10,background:"#ecfdf5",border:`2px solid ${C.acG}`,color:"#065f46",fontSize:14,fontWeight:600}}>✅ Knew it</button>
            <button onClick={()=>{setFlashScore(s=>({...s,wrong:s.wrong+1}));setFlashIdx(flashIdx+1);setFlashFlipped(false);}} style={{padding:"12px 32px",borderRadius:10,background:"#fef2f2",border:"2px solid #fecaca",color:"#991b1b",fontSize:14,fontWeight:600}}>❌ Didn't know</button>
          </div>}
        </div>)}
      </div>)}

      {/* ══════ MISSIONS ══════ */}
      {view==="missions"&&(<div style={{animation:"fadeUp .3s"}}>
        <div style={{fontSize:12,fontWeight:600,color:C.mt,letterSpacing:1,textTransform:"uppercase",marginBottom:14}}>⚡ All Study Missions</div>
        {DB.domains.map(d=>{const allT=d.objectives.flatMap(o=>o.topics.flatMap(t=>(t.tasks||[]).map((task,i)=>({task,key:`${t.id}-${i}`,topic:t.title}))));if(!allT.length)return null;const dn=allT.filter(x=>tasks[x.key]).length;return(
          <div key={d.id} style={{marginBottom:16}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}><span style={{fontSize:18}}>{d.icon}</span><span style={{fontSize:14,fontWeight:600,color:d.color}}>{d.title}</span><span style={{fontSize:12,color:C.mt,fontWeight:500}}>({dn}/{allT.length})</span></div>
            {allT.map(({task,key,topic})=>{const d2=tasks[key];return(
              <button key={key} onClick={()=>togTask(key)} style={{width:"100%",display:"flex",alignItems:"start",gap:10,padding:"10px 14px",marginBottom:4,background:d2?"#f0fdf4":C.cd,border:`1px solid ${d2?"#bbf7d0":C.bd}`,borderRadius:10,textAlign:"left",boxShadow:C.shadow}}>
                <div style={{width:18,height:18,borderRadius:5,flexShrink:0,marginTop:2,background:d2?C.warn:"#f3f4f6",border:`2px solid ${d2?C.warn:"#d1d5db"}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:9,color:"#fff"}}>{d2?"✓":""}</div>
                <div><div style={{fontSize:11,color:C.mt,fontWeight:500}}>{topic}</div><div style={{fontSize:13,color:d2?"#6b7280":C.tx,textDecoration:d2?"line-through":"none",lineHeight:1.4}}>{task}</div></div>
              </button>
            );})}
          </div>
        );})}
      </div>)}

      {/* ══════ PBQ LAB ══════ */}
      {view==="pbq"&&(<div style={{animation:"fadeUp .3s"}}>
        <div style={{fontSize:12,fontWeight:600,color:C.ac2,letterSpacing:1,textTransform:"uppercase",marginBottom:14}}>🖥️ Performance-Based Questions</div>
        {!pbq?(
          PBQS.map(p=><button key={p.id} className="card" onClick={()=>setPbq({...p,selected:[],submitted:false})} style={{width:"100%",background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:18,marginBottom:10,textAlign:"left",boxShadow:C.shadow}}>
            <div style={{fontSize:16,fontWeight:700,color:C.br}}>{p.title}</div>
            <div style={{fontSize:12,color:C.mt,marginTop:4}}>Domain {p.domain} · Difficulty: {"⭐".repeat(p.diff)} · +{XP.pbq} XP</div>
            <div style={{fontSize:12,color:"#6b7280",marginTop:8,lineHeight:1.5}}>{p.scenario.slice(0,150)}...</div>
          </button>)
        ):(
          <div>
            <button onClick={()=>setPbq(null)} style={{background:"none",border:"none",color:C.ac,fontSize:13,fontWeight:500,marginBottom:12}}>← Back to PBQ list</button>
            <div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:20,marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:18,fontWeight:700,color:C.br,marginBottom:10}}>{pbq.title}</div>
              <pre style={{fontSize:12,color:C.tx,lineHeight:1.7,whiteSpace:"pre-wrap",background:"#f1f5f9",padding:14,borderRadius:10,border:`1px solid ${C.bd}`}}>{pbq.scenario}</pre>
            </div>

            {/* Firewall rules PBQ */}
            {pbq.rules&&(<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:18,marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:12,color:C.mt,fontWeight:500,marginBottom:10}}>Select the correct rules:</div>
              {pbq.rules.map(r=>{const sel=pbq.selected.includes(r.id);const isCorr=pbq.submitted&&r.correct;const isWrong=pbq.submitted&&sel&&!r.correct;
                return <button key={r.id} disabled={pbq.submitted} onClick={()=>setPbq(p=>({...p,selected:sel?p.selected.filter(x=>x!==r.id):[...p.selected,r.id]}))} style={{width:"100%",padding:"12px 14px",marginBottom:5,borderRadius:10,textAlign:"left",fontSize:13,border:`2px solid ${isCorr?"#06d6a0":isWrong?"#ef4444":sel?C.ac:C.bd}`,background:isCorr?"#ecfdf5":isWrong?"#fef2f2":sel?"#eff6ff":"#fff",color:isCorr?"#065f46":isWrong?"#991b1b":sel?C.ac:C.tx}}>
                  {sel?"☑":"☐"} {r.text}{pbq.submitted&&isCorr?" ✓":""}{pbq.submitted&&isWrong?" ✗":""}
                </button>
              })}
            </div>)}

            {/* Log analysis PBQ */}
            {pbq.options&&(<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:18,marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:12,color:C.mt,fontWeight:500,marginBottom:10}}>Select the correct analysis:</div>
              {pbq.options.map(o=>{const sel=pbq.selected.includes(o.id);const isCorr=pbq.submitted&&o.correct;const isWrong=pbq.submitted&&sel&&!o.correct;
                return <button key={o.id} disabled={pbq.submitted} onClick={()=>setPbq(p=>({...p,selected:[o.id]}))} style={{width:"100%",padding:"12px 14px",marginBottom:5,borderRadius:10,textAlign:"left",fontSize:13,border:`2px solid ${isCorr?"#06d6a0":isWrong?"#ef4444":sel?C.ac:C.bd}`,background:isCorr?"#ecfdf5":isWrong?"#fef2f2":sel?"#eff6ff":"#fff",color:isCorr?"#065f46":isWrong?"#991b1b":sel?C.ac:C.tx}}>
                  {sel?"◉":"○"} {o.text}
                </button>
              })}
            </div>)}

            {/* IR ordering PBQ */}
            {pbq.steps&&(<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:18,marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:12,color:C.mt,fontWeight:500,marginBottom:10}}>Click steps in correct order (NIST SP 800-61):</div>
              {pbq.steps.map(s=>{const idx=pbq.selected.indexOf(s.id);const sel=idx!==-1;const isCorr=pbq.submitted&&idx===s.order-1;const isWrong=pbq.submitted&&sel&&idx!==s.order-1;
                return <button key={s.id} disabled={pbq.submitted} onClick={()=>setPbq(p=>({...p,selected:sel?p.selected.filter(x=>x!==s.id):[...p.selected,s.id]}))} style={{width:"100%",padding:"12px 14px",marginBottom:5,borderRadius:10,textAlign:"left",fontSize:13,border:`2px solid ${isCorr?"#06d6a0":isWrong?"#ef4444":sel?C.ac:C.bd}`,background:isCorr?"#ecfdf5":isWrong?"#fef2f2":sel?"#eff6ff":"#fff",color:isCorr?"#065f46":isWrong?"#991b1b":sel?C.ac:C.tx}}>
                  {sel?`${idx+1}.`:"○"} {s.text} {pbq.submitted&&<span style={{fontSize:11,color:C.mt}}>({s.phase})</span>}
                </button>
              })}
            </div>)}

            {!pbq.submitted?<button onClick={()=>{setPbq(p=>({...p,submitted:true}));giveXp(XP.pbq,"PBQ Completed");}} style={{width:"100%",padding:16,borderRadius:12,background:C.ac2,color:"#fff",border:"none",fontSize:14,fontWeight:700,boxShadow:"0 4px 14px rgba(114,9,183,0.3)"}}>SUBMIT PBQ</button>
            :<div style={{background:C.cd,border:`1px solid ${C.bd}`,borderRadius:14,padding:20,boxShadow:C.shadow}}>
              <div style={{fontSize:15,fontWeight:700,color:C.acG,marginBottom:8}}>✓ PBQ Complete — +{XP.pbq} XP</div>
              <div style={{fontSize:13,color:"#6b7280",lineHeight:1.7}}>{pbq.explain}</div>
            </div>}
          </div>
        )}
      </div>)}

      {/* ══════ SHADOW EXAM ══════ */}
      {view==="exam"&&!quiz&&(<div style={{animation:"fadeUp .3s"}}>
        <div style={{background:`linear-gradient(135deg,#fef2f2,#fff1f2)`,border:"2px solid #fecaca",borderRadius:18,padding:32,textAlign:"center",boxShadow:"0 8px 30px rgba(239,68,68,0.1)"}}>
          <div style={{fontSize:56,marginBottom:12}}>🎯</div>
          <div style={{fontSize:24,fontWeight:800,color:"#991b1b"}}>Shadow Exam Mode</div>
          <p style={{fontSize:14,color:"#6b7280",marginTop:10,lineHeight:1.7,maxWidth:520,margin:"10px auto 0"}}>
            40 questions weighted by domain importance. Wording is harder than the actual CompTIA exam. Passing: 83% (750/900). Rate your confidence after each question.
          </p>
          <button onClick={startShadow} style={{marginTop:20,padding:"14px 36px",borderRadius:12,background:"#ef4444",color:"#fff",border:"none",fontSize:16,fontWeight:700,boxShadow:"0 4px 16px rgba(239,68,68,0.3)"}}>BEGIN SHADOW EXAM</button>
        </div>
      </div>)}

      </main>
    </div>
  );
}
