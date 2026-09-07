// Author-authored section blueprints, not copies of licensed framework text or submission schemas.
const families=[
 ['FedRAMP','CR26 / 2026; applicability review required','https://www.fedramp.gov/schemas/',[
 ['fedramp-ocr','Ongoing Certification Report',['Offering and reporting period','Certification posture','Material changes','Vulnerabilities and incidents','Monitoring activities','Decisions and follow-up']],
 ['fedramp-sdr','Security Decision Record',['Decision and scope','Applicable requirements','Evidence and alternatives','Risk rationale','Approvers and review date']],
 ['fedramp-scg','Secure Configuration Guide',['Offering boundary','Customer responsibilities','Secure configuration instructions','Validation procedures','Exceptions and version history']],
 ['fedramp-vdr','Vulnerability Detail Report',['Affected assets','Detection and source evidence','Evaluation and prioritization','Remediation and milestones','Retest evidence']],
 ['fedramp-ver','Vulnerability Evaluation and Reporting record',['Evaluation population','Method and version','Vulnerability evaluations','Reporting history','Acceptance and escalation']],
 ['fedramp-pain','PAIN evaluation worksheet',['Applicable VER definitions','Input evidence','Rating rationale','Evaluator and approval','Reassessment triggers']],
 ['fedramp-change','Significant change notification draft',['Offering and change category','Reason and description','Customer and security impact','Implementation timeline','Validation plan and assessor involvement']],
 ['fedramp-incident','Incident report draft',['Offering and incident timeline','Affected systems and information','Containment and recovery','Notifications','Lessons and corrective actions']]]],
 ['FedRAMP Rev5','NIST SP 800-53 Rev. 5; baseline and CR26 applicability required','https://www.fedramp.gov/2026/providers/rev5/',[
 ['fedramp-ssp','System Security Plan',['Boundary and categorization','Architecture and data flows','Control implementations and parameters','Inherited responsibilities','Evidence and attachments']],
 ['fedramp-sap','Security Assessment Plan',['Assessment scope','Objectives and procedures','Assessor independence','Sampling and schedule','Rules of engagement']],
 ['fedramp-sar','Security Assessment Report draft',['Scope and methodology','Test results','Findings and risks','Limitations','Independent assessor conclusions']],
 ['fedramp-poam','Plan of Action and Milestones',['Weaknesses and sources','Risk and ownership','Milestones and dependencies','Due dates','Closure validation']]]],
 ['SOC 2','2017 TSC; revised points of focus 2022; report type and period required','https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services',[
 ['soc2-workpaper','Control testing workpaper',['Control and criteria','Design and operating effectiveness objective','Population and completeness','Sample selection and procedures','Evidence and test results','Exceptions and reviewer conclusion']],
 ['soc2-system','System description draft',['Services and commitments','System components and boundary','Processes and controls','Subservice organizations and complementary controls','Incidents and significant changes']],
 ['soc2-assertion','Management assertion draft',['System and period','Applicable criteria','Management responsibilities','Basis and exceptions','Authorized management signature']],
 ['soc2-evidence','Evidence request register',['Request and control','Owner and system of record','Population and period','Quality requirements','Collection status and location']],
 ['soc2-findings','Exception and finding register',['Finding and affected criteria','Evidence and root cause','Severity and report impact','Owner and milestones','Remediation and retest']]]],
 ['CMMC L2','SP 800-171 Rev. 2; assessment applicability review required','https://dodcio.defense.gov/cmmc/Resources-Documentation/',[
 ['cmmc-ssp','CMMC System Security Plan',['Assessment boundary and assets','CUI categories and flows','Requirement implementations','Shared responsibilities','Evidence and reviews']],
 ['cmmc-poam','CMMC POA&M draft',['Unmet requirements','Eligibility and assessment constraints','Risk and ownership','Milestones and deadlines','Closure assessment']],
 ['cmmc-fips','Cryptographic module validation register',['Module and certificate identifiers','Version and operational environment','Approved mode and deployment evidence','Certificate status and review date','Gaps and compensating decisions']],
 ['cmmc-dataflow','CUI dataflow specification',['CUI sources and destinations','Assets and trust boundaries','Storage processing and transmission','Encryption and access controls','Validated diagram and owner review']],
 ['cmmc-assessment','Assessment objective workbook',['Requirements and objectives','Examine interview and test procedures','Evidence and scope','Findings and scoring basis','Assessor review']]]],
 ['ISO 27001','2022; organization scope and Statement of Applicability required','https://www.iso.org/standard/27001',[
 ['iso27001-scope','ISMS scope and context',['Business context','Interested parties and obligations','Boundary and interfaces','Exclusions and justification','Owner approval']],
 ['iso27001-isms','ISMS core documentation',['Scope and policy','Roles and responsibilities','Risk methodology and treatment','Objectives and communication','Performance evaluation and improvement']],
 ['iso27001-soa','Statement of Applicability draft',['Control applicability','Inclusion and exclusion rationale','Implementation status','Risk treatment linkage','Evidence and approval']],
 ['iso27001-policy','Policy and procedure record',['Purpose scope and owner','Policy commitments','Operating procedures and exceptions','Evidence contracts and testing','Approval version and review date']],
 ['iso27001-audit','Internal audit workpapers',['Audit program and independence','Scope and criteria','Testing and evidence','Nonconformities','Corrective actions and follow-up']],
 ['iso27001-management','Management review record',['Inputs and objectives','Performance and audit results','Risks and changes','Decisions and resources','Actions owners and follow-up']]]],
 ['ISO 42001','2023; AI system scope and applicability review required','https://www.iso.org/standard/42001',[
 ['iso42001-aims','AI management system documentation',['Scope and AI inventory','Policy responsibilities and objectives','Risk and impact assessment','Lifecycle controls and oversight','Monitoring and improvement']],
 ['iso42001-system','AI system documentation',['Purpose and intended use','Model development and lineage','Data provenance and evaluation splits','Performance thresholds and limitations','Risk treatment','Human oversight and stop conditions']],
 ['iso42001-impact','AI impact and risk assessment',['Affected parties and context','Foreseeable impacts and misuse','Evaluation evidence','Treatment and residual risk','Approval and reassessment']],
 ['iso42001-soa','AIMS Statement of Applicability draft',['Applicable controls','Selection rationale','Implementation and responsibilities','Risk linkage and evidence','Review and approval']]]]
];
export const REPORT_TEMPLATES=families.flatMap(([framework,edition,source,rows])=>rows.map(([id,title,sections])=>({id,title,framework,edition,source,sections,status:'DRAFT_BLUEPRINT',schemaValidated:false})));
