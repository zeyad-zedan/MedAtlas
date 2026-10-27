import type { OptionKey, DifficultyLevel } from '../lib/mcq-engine.ts';

export interface SeedSubject {
  slug: string;
  title: string;
  description: string;
  displayOrder: number;
  lectures: Array<{
    title: string;
    description: string;
    lectureNumber: number;
    estimatedMinutes: number;
    educationalNotes: string;
    questions: Array<{
      questionText: string;
      optionA: string;
      optionB: string;
      optionC: string;
      optionD: string;
      correctAnswer: OptionKey;
      explanation: string;
      explanationA: string;
      explanationB: string;
      explanationC: string;
      explanationD: string;
      difficulty: DifficultyLevel;
      tags: string;
      diagramSvg?: string;
    }>;
  }>;
}

const CELL_MEMBRANE_SVG = `<svg viewBox="0 0 560 180" xmlns="http://www.w3.org/2000/svg" class="w-full h-auto rounded-lg border border-slate-200 bg-white p-3">
  <rect width="560" height="180" fill="#F8FAFC"/>
  <text x="18" y="26" font-family="Plus Jakarta Sans, sans-serif" font-size="12" font-weight="700" fill="#0F172A">Vesicular Trafficking Pathway: RER → Cis-Golgi → Trans-Golgi → Secretory Granule</text>
  <rect x="20" y="52" width="110" height="90" rx="8" fill="#E0F2FE" stroke="#0284C7" stroke-width="1.5"/>
  <text x="75" y="90" text-anchor="middle" font-family="Plus Jakarta Sans, sans-serif" font-size="11" font-weight="600" fill="#0369A1">Rough ER</text>
  <text x="75" y="108" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#0F172A">N-Glycosylation</text>
  <path d="M 135 97 L 178 97" stroke="#0284C7" stroke-width="2" marker-end="url(#arrow)"/>
  <text x="156" y="88" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#0284C7">COPII</text>
  <rect x="185" y="52" width="145" height="90" rx="8" fill="#FEF3C7" stroke="#D97706" stroke-width="1.5"/>
  <text x="257" y="84" text-anchor="middle" font-family="Plus Jakarta Sans, sans-serif" font-size="11" font-weight="600" fill="#B45309">Golgi Apparatus</text>
  <text x="257" y="102" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#0F172A">O-Glycosylation &amp; M6P</text>
  <text x="257" y="118" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#78350F">COPI Retrograde</text>
  <path d="M 335 97 L 385 97" stroke="#059669" stroke-width="2"/>
  <text x="360" y="88" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#059669">Clathrin</text>
  <rect x="392" y="52" width="145" height="90" rx="8" fill="#ECFDF5" stroke="#059669" stroke-width="1.5"/>
  <text x="464" y="88" text-anchor="middle" font-family="Plus Jakarta Sans, sans-serif" font-size="11" font-weight="600" fill="#047857">Lysosome / Secretion</text>
  <text x="464" y="106" text-anchor="middle" font-family="IBM Plex Mono, monospace" font-size="9" fill="#0F172A">Mannose-6-Phosphate</text>
</svg>`;

const SA_NODE_SVG = `<svg viewBox="0 0 560 190" xmlns="http://www.w3.org/2000/svg" class="w-full h-auto rounded-lg border border-slate-200 bg-white p-3">
  <rect width="560" height="190" fill="#F8FAFC"/>
  <text x="18" y="24" font-family="Plus Jakarta Sans, sans-serif" font-size="12" font-weight="700" fill="#0F172A">Sinoatrial (SA) Nodal Action Potential Trace</text>
  <line x1="55" y1="38" x2="55" y2="162" stroke="#64748B" stroke-width="1.5"/>
  <line x1="55" y1="162" x2="520" y2="162" stroke="#64748B" stroke-width="1.5"/>
  <line x1="55" y1="115" x2="520" y2="115" stroke="#94A3B8" stroke-dasharray="4 4" stroke-width="1"/>
  <text x="48" y="60" text-anchor="end" font-family="IBM Plex Mono, monospace" font-size="10" fill="#334155">+10 mV</text>
  <text x="48" y="118" text-anchor="end" font-family="IBM Plex Mono, monospace" font-size="10" fill="#334155">-40 mV</text>
  <text x="48" y="154" text-anchor="end" font-family="IBM Plex Mono, monospace" font-size="10" fill="#334155">-60 mV</text>
  <path d="M 65 150 L 175 115 Q 215 48 245 55 Q 280 65 325 150 L 435 115 Q 470 50 500 58" fill="none" stroke="#0284C7" stroke-width="3"/>
  <text x="120" y="144" font-family="IBM Plex Mono, monospace" font-size="10" font-weight="600" fill="#0F172A">Phase 4 (If Na+)</text>
  <text x="195" y="82" font-family="IBM Plex Mono, monospace" font-size="10" font-weight="600" fill="#DC2626">Phase 0 (ICa-L)</text>
  <text x="295" y="102" font-family="IBM Plex Mono, monospace" font-size="10" font-weight="600" fill="#059669">Phase 3 (IK)</text>
</svg>`;

export const INITIAL_CURRICULUM_SEED: SeedSubject[] = [
  {
    slug: 'histology-cell-biology',
    title: 'Histology & Cell Biology',
    description:
      'Microscopic anatomy of cells, intracellular protein trafficking, membrane transport mechanisms, and extracellular matrix disorders.',
    displayOrder: 1,
    lectures: [
      {
        title: 'Eukaryotic Cell Ultrastructure & Membrane Transport',
        description:
          'Covers rough and smooth endoplasmic reticulum, Golgi vesicular transport (COPI, COPII, clathrin), lysosomal targeting, and active/passive membrane transport.',
        lectureNumber: 1,
        estimatedMinutes: 35,
        educationalNotes:
          'Key Clinical Pearls:\n• Rough ER (Nissl bodies in neurons) performs N-linked glycosylation on asparagine residues and signal-peptide cleavage.\n• Golgi apparatus performs O-linked glycosylation on serine/threonine residues and phosphorylates mannose residues (Mannose-6-Phosphate) to target acid hydrolases to lysosomes.\n• I-cell disease (Mucolipidosis type II): Deficiency of N-acetylglucosamine-1-phosphotransferase leads to failure of mannose phosphorylation in the Golgi; lysosomal enzymes are secreted extracellularly instead of reaching lysosomes, causing coarse facial features, corneal clouding, and restricted joint mobility.\n• COPII mediates anterograde transport (RER → cis-Golgi); COPI mediates retrograde transport (Golgi → RER).',
        questions: [
          {
            questionText:
              'A 9-month-old infant presents with coarse facial features, gingival hyperplasia, corneal clouding, and developmental delay. Laboratory assay of cultured fibroblasts shows markedly decreased intracellular lysosomal hydrolase activity, while serum levels of these same hydrolases are significantly elevated. Defective phosphorylation of which carbohydrate residue in the Golgi apparatus best explains this patient’s condition?',
            optionA: 'Galactose on sphingolipids',
            optionB: 'Mannose on N-linked oligosaccharides',
            optionC: 'Serine-linked N-acetylgalactosamine',
            optionD: 'Sialic acid on gangliosides',
            correctAnswer: 'B',
            explanation:
              'Inclusion-cell (I-cell) disease (mucolipidosis type II) results from a deficiency of N-acetylglucosamine-1-phosphotransferase in the cis-Golgi, preventing phosphorylation of mannose residues to mannose-6-phosphate (M6P) on N-linked glycoproteins. Without the M6P targeting signal, acid hydrolases are secreted extracellularly rather than routed to lysosomes.',
            explanationA:
              'Galactose modification occurs in the trans-Golgi network and is not the targeting signal for lysosomal acid hydrolases.',
            explanationB:
              'Correct: Mannose-6-phosphate (M6P) is the essential recognition marker required for clathrin-mediated transport of acid hydrolases from the trans-Golgi to lysosomes.',
            explanationC:
              'O-linked glycosylation on serine or threonine residues occurs in the Golgi but does not direct lysosomal enzyme trafficking.',
            explanationD:
              'Sialic acid degradation defects cause sialidosis, not extracellular leakage of multiple lysosomal enzymes.',
            difficulty: 'Medium',
            tags: 'Organelles,Protein Trafficking,Lysosomal Storage',
            diagramSvg: CELL_MEMBRANE_SVG,
          },
          {
            questionText:
              'In a molecular cell biology experiment, researchers inhibit a coat protein complex, causing newly synthesized secretory proteins to accumulate inside the rough endoplasmic reticulum (RER) lumen without reaching the cis-Golgi cisternae. Which vesicular coat protein was directly inhibited?',
            optionA: 'Clathrin',
            optionB: 'COPI (Coatomer Protein I)',
            optionC: 'COPII (Coatomer Protein II)',
            optionD: 'Caveolin-1',
            correctAnswer: 'C',
            explanation:
              'COPII-coated vesicles exclusively mediate anterograde vesicular transport budding from the rough endoplasmic reticulum (RER) toward the cis-Golgi apparatus.',
            explanationA:
              'Clathrin mediates vesicular transport between the trans-Golgi network and lysosomes as well as receptor-mediated endocytosis at the plasma membrane.',
            explanationB:
              'COPI mediates retrograde transport from the cis-Golgi back to the rough endoplasmic reticulum to recycle ER-resident proteins carrying KDEL sequences.',
            explanationC:
              'Correct: COPII drives anterograde export from the RER to the cis-Golgi; inhibiting COPII traps secretory proteins inside the RER.',
            explanationD:
              'Caveolin-1 forms plasma membrane caveolae involved in signal transduction and potocytosis.',
            difficulty: 'Easy',
            tags: 'Vesicular Transport,Organelles,Golgi Apparatus',
          },
          {
            questionText:
              'A 46-year-old man with congestive heart failure is treated with digoxin. Digoxin increases cardiac contractility by directly inhibiting which primary active transport protein on the cardiomyocyte sarcolemma?',
            optionA: 'Sarcolemmal Na+/Ca2+ exchanger (NCX)',
            optionB: 'Sarcoplasmic/endoplasmic reticulum Ca2+-ATPase (SERCA2)',
            optionC: 'Na+/K+-ATPase pump',
            optionD: 'L-type voltage-gated Ca2+ channel',
            correctAnswer: 'C',
            explanation:
              'Digoxin directly inhibits the alpha-subunit of the sarcolemmal Na+/K+-ATPase pump. The resulting rise in intracellular Na+ reduces the inward Na+ gradient driving the Na+/Ca2+ exchanger (NCX), decreasing Ca2+ extrusion and increasing sarcoplasmic reticulum Ca2+ stores for positive inotropy.',
            explanationA:
              'The Na+/Ca2+ exchanger is secondarily slowed due to elevated intracellular Na+, not directly inhibited by digoxin.',
            explanationB:
              'SERCA2 pumps Ca2+ back into the sarcoplasmic reticulum and is regulated by phospholamban, not digoxin.',
            explanationC:
              'Correct: Cardiac glycosides directly bind and inhibit the extracellular K+-binding site of Na+/K+-ATPase.',
            explanationD:
              'L-type Ca2+ channels are blocked by dihydropyridines, verapamil, and diltiazem.',
            difficulty: 'Easy',
            tags: 'Membrane Transport,Na/K ATPase,Excitation-Contraction',
          },
          {
            questionText:
              'A 6-year-old boy is evaluated for recurrent sinopulmonary infections, bronchiectasis, and situs inversus totalis on chest radiograph. Electron microscopy of his respiratory cilia is most likely to demonstrate a defect in which cytoskeletal motor protein?',
            optionA: 'Kinesin heavy chain',
            optionB: 'Axonemal dynein',
            optionC: 'Cytoplasmic myosin II',
            optionD: 'Microtubule-associated tau protein',
            correctAnswer: 'B',
            explanation:
              'Primary ciliary dyskinesia (Kartagener syndrome) is caused by a congenital defect in axonemal dynein arms, which connect peripheral microtubule doublets in the 9+2 ciliary axoneme and generate ciliary beating.',
            explanationA:
              'Kinesin mediates anterograde axonal transport toward the (+) end of microtubules.',
            explanationB:
              'Correct: Absence or dysfunction of outer/inner axonemal dynein arms prevents sliding of adjacent microtubule doublets in motile cilia and flagella.',
            explanationC:
              'Myosin II interacts with actin microfilaments for muscle contraction and cytokinesis.',
            explanationD:
              'Tau stabilizes axonal microtubules in CNS neurons and forms neurofibrillary tangles in Alzheimer disease.',
            difficulty: 'Medium',
            tags: 'Cytoskeleton,Cilia,Microtubules',
          },
        ],
      },
      {
        title: 'Connective Tissue, Extracellular Matrix & Collagen Disorders',
        description:
          'Examines collagen biosynthesis (Types I–IV), elastin cross-linking by lysyl oxidase, and hereditary disorders of the extracellular matrix.',
        lectureNumber: 2,
        estimatedMinutes: 30,
        educationalNotes:
          'Collagen Biosynthesis Steps:\n1. Intracellular (RER): Synthesis of preprocollagen alpha chains (Gly-X-Y repeat); hydroxylation of proline & lysine residues (requires Vitamin C / ascorbate as cofactor); glycosylation of hydroxylysine and triple-helix assembly into procollagen.\n2. Extracellular: Cleavage of N- and C-terminal propeptides by procollagen peptidases → tropocollagen; covalent cross-linking of lysine-hydroxylysine residues by copper-dependent lysyl oxidase.\n\nMajor Collagen Types:\n• Type I: Bone, skin, tendon, dentin, fascia, cornea, late wound repair (defective in Osteogenesis Imperfecta).\n• Type II: Cartilage, vitreous body, nucleus pulposus.\n• Type III: Reticulin — blood vessels, uterus, fetal tissue, early wound granulation tissue (defective in vascular Ehlers-Danlos).\n• Type IV: Basement membrane / basal lamina — glomerulus, cochlea, lens capsule (defective in Alport syndrome; targeted in Goodpasture syndrome).',
        questions: [
          {
            questionText:
              'A 72-year-old man who lives alone and subsists primarily on toast and black tea presents with bleeding gums, perifollicular hemorrhages, corkscrew hairs, and poor wound healing. The impaired step of collagen synthesis in this patient normally occurs in which cellular compartment?',
            optionA: 'Extracellular space via copper-dependent lysyl oxidase',
            optionB: 'Rough endoplasmic reticulum lumen via prolyl and lysyl hydroxylases',
            optionC: 'Trans-Golgi network via procollagen N-peptidase',
            optionD: 'Cytosolic ribosome via glycine tRNA synthetase',
            correctAnswer: 'B',
            explanation:
              'Scurvy (vitamin C / ascorbic acid deficiency) impairs the hydroxylation of proline and lysine residues on pro-alpha collagen chains inside the lumen of the rough endoplasmic reticulum (RER). Ascorbic acid is required to maintain the iron cofactor (Fe2+) of prolyl and lysyl hydroxylases in its reduced state.',
            explanationA:
              'Extracellular cross-linking via lysyl oxidase requires copper (defective in Menkes disease), not vitamin C.',
            explanationB:
              'Correct: Prolyl and lysyl hydroxylation takes place co-translationally and post-translationally inside the RER lumen and requires vitamin C.',
            explanationC:
              'Cleavage of terminal propeptides by procollagen peptidases occurs extracellularly and is impaired in arthrochalasia-type Ehlers-Danlos syndrome.',
            explanationD:
              'Translation of Gly-X-Y repeats occurs on RER-bound ribosomes and does not require vitamin C.',
            difficulty: 'Easy',
            tags: 'Collagen,Extracellular Matrix,Vitamin Deficiency',
          },
          {
            questionText:
              'A 19-year-old man presents with progressive sensorineural hearing loss, microscopic hematuria, and bilateral anterior lenticonus. Electron microscopy of a renal biopsy reveals splitting and lamination ("basket-weave" appearance) of the glomerular basement membrane. Which collagen type is mutated in this patient?',
            optionA: 'Type I collagen',
            optionB: 'Type II collagen',
            optionC: 'Type III collagen',
            optionD: 'Type IV collagen',
            correctAnswer: 'D',
            explanation:
              'Alport syndrome is caused by mutations in COL4A5 (most commonly X-linked) encoding the alpha-5 chain of Type IV collagen, the principal structural component of the glomerular basement membrane, cochlear stria vascularis, and ocular lens capsule.',
            explanationA:
              'Type I collagen mutations cause osteogenesis imperfecta (multiple fractures, blue sclerae, conductive hearing loss).',
            explanationB:
              'Type II collagen forms hyaline cartilage and vitreous humor.',
            explanationC:
              'Type III collagen mutations cause vascular Ehlers-Danlos syndrome (berry aneurysms, hollow organ rupture).',
            explanationD:
              'Correct: Type IV collagen forms the non-fibrillar network of basement membranes in the kidney, ear, and eye.',
            difficulty: 'Medium',
            tags: 'Collagen,Basement Membrane,Genetics',
          },
          {
            questionText:
              'A 23-year-old tall, slender basketball player presents with acute tearing chest pain radiating to his back. Examination reveals arachnodactyly, pectus excavatum, and bilateral upward lens subluxation (ectopia lentis). His condition results from a mutation in the gene encoding which extracellular matrix protein?',
            optionA: 'Elastin',
            optionB: 'Fibrillin-1',
            optionC: 'Procollagen alpha-1(I)',
            optionD: 'Lysyl hydroxylase',
            correctAnswer: 'B',
            explanation:
              'Marfan syndrome is an autosomal dominant connective tissue disorder caused by mutations in FBN1, which encodes fibrillin-1. Fibrillin-1 forms the glycoprotein microfibrillar scaffold around elastin fibers and sequesters TGF-beta in the tunica media of the aorta and ciliary zonules of the lens.',
            explanationA:
              'Elastin gene deletion on chromosome 7q11.23 causes supravalvular aortic stenosis in Williams syndrome.',
            explanationB:
              'Correct: Defective fibrillin-1 compromises elastic microfibrils in the ascending aorta and suspensory ligaments of the lens.',
            explanationC:
              'Procollagen alpha-1(I) mutations cause osteogenesis imperfecta.',
            explanationD:
              'Lysyl hydroxylase deficiency causes kyphoscoliotic Ehlers-Danlos syndrome.',
            difficulty: 'Easy',
            tags: 'Elastic Fibers,Extracellular Matrix,Connective Tissue',
          },
        ],
      },
    ],
  },
  {
    slug: 'medical-physiology',
    title: 'Medical Physiology',
    description:
      'Quantitative cellular and organ-system physiology covering cardiac electrophysiology, hemodynamics, and renal glomerular clearance.',
    displayOrder: 2,
    lectures: [
      {
        title: 'Cardiac Action Potentials & Hemodynamics',
        description:
          'Contrasts pacemaker (SA/AV node) and non-pacemaker (ventricular myocyte) action potentials, Wiggers diagram phases, and pressure-volume loops.',
        lectureNumber: 1,
        estimatedMinutes: 40,
        educationalNotes:
          'Pacemaker Action Potential (SA & AV Nodes):\n• Phase 4: Slow spontaneous depolarization via "funny" Na+ current (If) and T-type Ca2+ channels. Slope determines heart rate (increased by sympathetic beta-1 stimulation; decreased by parasympathetic M2 stimulation).\n• Phase 0: Depolarization upstroke mediated by slow voltage-gated L-type Ca2+ channels (ICa-L) opening near -40 mV.\n• Phase 3: Repolarization mediated by inactivation of Ca2+ channels and increased K+ efflux via delayed rectifier K+ channels (IK).\n• Phases 1 & 2 are absent in pacemaker cells.\n\nVentricular Myocyte Action Potential:\n• Phase 0: Fast Na+ influx (INa); Phase 1: Transient outward K+ current (Ito); Phase 2: Plateau balancing L-type Ca2+ influx with K+ efflux; Phase 3: Rapid repolarization via K+ efflux; Phase 4: Stable resting potential (-90 mV) maintained by inward rectifier K+ channels (IK1).',
        questions: [
          {
            questionText:
              'During a cardiac electrophysiology study, administration of verapamil slows conduction velocity through the atrioventricular (AV) node and prolongs the PR interval on surface ECG. Which phase and ionic current of the AV nodal action potential is directly suppressed by this medication?',
            optionA: 'Phase 0 fast inward Na+ current (INa)',
            optionB: 'Phase 0 inward L-type Ca2+ current (ICa-L)',
            optionC: 'Phase 3 outward delayed rectifier K+ current (IK)',
            optionD: 'Phase 4 inward rectifier K+ current (IK1)',
            correctAnswer: 'B',
            explanation:
              'Nondihydropyridine calcium channel blockers (verapamil, diltiazem) block L-type voltage-gated Ca2+ channels (ICa-L). Because SA and AV nodal cells rely on ICa-L for their Phase 0 depolarization upstroke, blocking ICa-L decreases the slope of Phase 0 in the AV node and slows AV nodal conduction.',
            explanationA:
              'Fast Na+ channels (INa) drive Phase 0 in ventricular myocytes and His-Purkinje fibers (blocked by Class I antiarrhythmics), not in AV nodal pacemaker cells.',
            explanationB:
              'Correct: Phase 0 depolarization in SA and AV nodal tissue depends on L-type Ca2+ influx.',
            explanationC:
              'Phase 3 K+ channels (IK) are blocked by Class III antiarrhythmics (amiodarone, sotalol), prolonging action potential duration.',
            explanationD:
              'IK1 maintains the resting membrane potential in ventricular muscle and is absent in pacemaker cells.',
            difficulty: 'Easy',
            tags: 'Electrophysiology,SA Node,Cardiovascular',
            diagramSvg: SA_NODE_SVG,
          },
          {
            questionText:
              'On a standard Wiggers cardiac cycle diagram, during which phase are both the mitral valve and the aortic valve simultaneously closed while left ventricular pressure is rapidly rising?',
            optionA: 'Rapid ventricular ejection',
            optionB: 'Isovolumetric contraction',
            optionC: 'Isovolumetric relaxation',
            optionD: 'Atrial systole',
            correctAnswer: 'B',
            explanation:
              'Isovolumetric contraction begins immediately after mitral valve closure (S1 heart sound) and ends when left ventricular pressure exceeds aortic diastolic pressure (~80 mmHg) to open the aortic valve. During this interval, both valves are closed and ventricular volume remains constant while pressure rises steeply.',
            explanationA:
              'During rapid ventricular ejection, the aortic valve is open and blood is ejected into the aorta.',
            explanationB:
              'Correct: Both mitral and aortic valves are closed as ventricular tension develops at constant volume.',
            explanationC:
              'During isovolumetric relaxation, both valves are also closed, but left ventricular pressure is rapidly falling rather than rising.',
            explanationD:
              'During atrial systole, the mitral valve is open and the aortic valve is closed.',
            difficulty: 'Easy',
            tags: 'Cardiac Cycle,Hemodynamics,Valvular Physiology',
          },
          {
            questionText:
              'A 58-year-old woman receives an intravenous infusion of norepinephrine in the intensive care unit. Assuming reflex vagal activity is blocked with atropine, how will the left ventricular pressure-volume (PV) loop change in response to increased contractility (inotropy)?',
            optionA: 'Shift of the end-systolic pressure-volume relationship (ESPVR) to the left with decreased end-systolic volume (ESV)',
            optionB: 'Shift of the end-diastolic pressure-volume relationship (EDPVR) upward with decreased stroke volume',
            optionC: 'Increase in end-systolic volume (ESV) with no change in stroke volume',
            optionD: 'Decrease in peak systolic pressure with widened pulse volume',
            correctAnswer: 'A',
            explanation:
              'Positive inotropy (beta-1 adrenergic stimulation) increases the slope of the end-systolic pressure-volume relationship (ESPVR), shifting it leftward. The ventricle ejects more blood against a given afterload, reducing end-systolic volume (ESV) and increasing stroke volume (SV = EDV - ESV) and ejection fraction.',
            explanationA:
              'Correct: Increased contractility steepens the ESPVR line to the left, reducing ESV and increasing stroke volume.',
            explanationB:
              'Upward shift of the EDPVR reflects decreased ventricular compliance (diastolic dysfunction), not increased inotropy.',
            explanationC:
              'Increased ESV occurs with increased afterload or reduced contractility.',
            explanationD:
              'Positive inotropy increases peak left ventricular systolic pressure.',
            difficulty: 'Hard',
            tags: 'Hemodynamics,Pressure-Volume Loop,Inotropy',
          },
        ],
      },
      {
        title: 'Renal Clearance, GFR & Tubular Reabsorption',
        description:
          'Covers Starling forces in glomerular filtration, inulin vs PAH clearance, fractional excretion, and nephron segment transport.',
        lectureNumber: 2,
        estimatedMinutes: 35,
        educationalNotes:
          'Key Renal Equations:\n• Clearance: Cx = (Ux × V) / Px\n• Glomerular Filtration Rate (GFR) = Clearance of Inulin = Kf × [(PGC - PBS) - (πGC - πBS)]\n• Effective Renal Plasma Flow (eRPF) = Clearance of Para-aminohippuric acid (PAH)\n• Filtration Fraction (FF) = GFR / RPF (Normal ≈ 20%)\n\nArteriolar Resistance Effects:\n• Afferent arteriolar constriction (NSAIDs): ↓ PGC → ↓ GFR, ↓ RPF, No change in FF.\n• Efferent arteriolar constriction (Angiotensin II at low-moderate levels): ↑ PGC → ↑ GFR, ↓ RPF, ↑↑ FF.',
        questions: [
          {
            questionText:
              'In a renal physiology clearance study, a healthy volunteer has a plasma inulin concentration of 1.0 mg/mL, a urine inulin concentration of 60 mg/mL, and a urine flow rate of 2.0 mL/min. If the patient’s plasma glucose concentration is 1.0 mg/mL and urine glucose concentration is 0 mg/mL, what is the patient’s glomerular filtration rate (GFR)?',
            optionA: '30 mL/min',
            optionB: '60 mL/min',
            optionC: '120 mL/min',
            optionD: '240 mL/min',
            correctAnswer: 'C',
            explanation:
              'Inulin is freely filtered at the glomerulus and is neither reabsorbed nor secreted by the renal tubules; therefore, inulin clearance equals GFR. GFR = (U_inulin × V) / P_inulin = (60 mg/mL × 2.0 mL/min) / 1.0 mg/mL = 120 mL/min. Glucose is 100% reabsorbed in the proximal convoluted tubule via SGLT2/SGLT1 below the transport maximum (~375 mg/min), so its clearance is 0.',
            explanationA:
              '30 mL/min results from dividing rather than multiplying by urine flow rate.',
            explanationB:
              '60 mL/min omits the 2.0 mL/min urine flow rate factor (V).',
            explanationC:
              'Correct: Cinulin = (60 × 2.0) / 1.0 = 120 mL/min.',
            explanationD:
              '240 mL/min doubles the actual calculated inulin clearance.',
            difficulty: 'Medium',
            tags: 'Renal Clearance,GFR,Glomerular Physiology',
          },
          {
            questionText:
              'A 64-year-old man with bilateral renal artery stenosis is started on lisinopril (an ACE inhibitor). Three days later, his serum creatinine rises from 1.1 mg/dL to 2.4 mg/dL. Blocking angiotensin II synthesis caused a rapid drop in GFR primarily by producing which hemodynamic change at the glomerulus?',
            optionA: 'Constriction of the afferent arteriole',
            optionB: 'Dilation of the efferent arteriole',
            optionC: 'Constriction of the efferent arteriole',
            optionD: 'Increase in Bowman space hydrostatic pressure',
            correctAnswer: 'B',
            explanation:
              'In bilateral renal artery stenosis, renal perfusion pressure is reduced, and GFR is maintained by angiotensin II–mediated constriction of the efferent arteriole, which preserves glomerular capillary hydrostatic pressure (PGC). ACE inhibitors block angiotensin II formation, dilating the efferent arteriole and causing an acute fall in PGC and GFR.',
            explanationA:
              'Afferent arteriolar constriction is caused by prostaglandin inhibition (NSAIDs), not ACE inhibition.',
            explanationB:
              'Correct: Loss of angiotensin II dilates the efferent arteriole, reducing glomerular hydrostatic pressure (PGC) and filtration fraction.',
            explanationC:
              'Efferent arteriolar constriction is the normal action of angiotensin II, which ACE inhibitors prevent.',
            explanationD:
              'Increased Bowman space hydrostatic pressure occurs in post-renal urinary tract obstruction (e.g., ureteral calculi).',
            difficulty: 'Medium',
            tags: 'Renal Hemodynamics,RAAS,GFR',
          },
        ],
      },
    ],
  },
  {
    slug: 'systemic-pathology',
    title: 'Systemic Pathology',
    description:
      'Mechanisms of reversible vs irreversible cell injury, morphological patterns of necrosis, apoptosis pathways, and acute inflammation.',
    displayOrder: 3,
    lectures: [
      {
        title: 'Cellular Adaptation, Injury & Necrosis Patterns',
        description:
          'Differentiates reversible cellular swelling from irreversible membrane breakdown, and compares coagulative, liquefactive, caseous, and fat necrosis.',
        lectureNumber: 1,
        estimatedMinutes: 30,
        educationalNotes:
          'Hallmarks of Irreversible Cell Injury:\n• Severe plasma membrane damage (calcium influx activating phospholipases, proteases, endonucleases).\n• Mitochondrial permeability transition pore opening & release of cytochrome c into cytosol.\n• Nuclear pyknosis → karyorrhexis → karyolysis.\n\nMorphological Necrosis Patterns:\n• Coagulative necrosis: Ischemic infarction in solid organs (heart, kidney, spleen) EXCEPT brain; cell outlines preserved ("ghost cells") while nuclei disappear.\n• Liquefactive necrosis: CNS infarcts (microglial hydrolytic enzymes) and bacterial abscesses (neutrophilic enzymes).\n• Caseous necrosis: Tuberculosis & systemic dimorphic fungi; friable "cheesy" debris surrounded by epithelioid macrophages and Langhans giant cells.\n• Fat necrosis: Acute pancreatitis (lipase liberates fatty acids that bind Ca2+ via saponification) and breast trauma.',
        questions: [
          {
            questionText:
              'A 68-year-old woman dies 48 hours after sustaining an acute transmural myocardial infarction resulting from complete occlusion of the left anterior descending coronary artery. Histologic examination of the infarcted left ventricular myocardium is most likely to reveal which pattern of necrosis?',
            optionA: 'Liquefactive necrosis with cystic cavity formation',
            optionB: 'Coagulative necrosis with preserved eosinophilic cell outlines and loss of nuclei',
            optionC: 'Caseous necrosis with rimming Langhans multinucleated giant cells',
            optionD: 'Enzymatic fat necrosis with basophilic calcium soap deposition',
            correctAnswer: 'B',
            explanation:
              'Ischemic infarction in all solid organs except the brain produces coagulative necrosis. Acidosis from ischemia denatures both structural proteins and proteolytic enzymes, preserving the basic cellular architecture ("tombstone" or "ghost" myocytes) for several days while nuclei undergo karyolysis.',
            explanationA:
              'Liquefactive necrosis is characteristic of ischemic infarction in the central nervous system and suppurative bacterial infections.',
            explanationB:
              'Correct: Coagulative necrosis preserves eosinophilic cytoplasmic outlines while nuclear basophilia is lost.',
            explanationC:
              'Caseous necrosis is seen in Mycobacterium tuberculosis and Histoplasma/Coccidioides infections.',
            explanationD:
              'Enzymatic fat necrosis with dystrophic calcification (saponification) occurs in acute pancreatitis.',
            difficulty: 'Easy',
            tags: 'Cell Injury,Necrosis,Myocardial Infarction',
          },
          {
            questionText:
              'In an experimental model of hypoxic hepatocyte injury, which intracellular event marks the transition from reversible cellular swelling to irreversible cell death?',
            optionA: 'Detachment of ribosomes from the rough endoplasmic reticulum',
            optionB: 'Plasma membrane blebbing and loss of microvilli',
            optionC: 'Disruption of the mitochondrial permeability transition pore and plasma membrane rupture with massive Ca2+ influx',
            optionD: 'Clumping of nuclear chromatin triggered by cytosolic acidosis',
            correctAnswer: 'C',
            explanation:
              'Irreversible cell injury is defined by two critical thresholds: inability to reverse mitochondrial dysfunction (opening of the mitochondrial permeability transition pore with cytochrome c leakage) and profound loss of plasma membrane integrity permitting massive extracellular Ca2+ influx.',
            explanationA:
              'Ribosomal detachment and decreased protein synthesis are reversible features of early ATP depletion.',
            explanationB:
              'Hydropic swelling, plasma membrane blebbing, and loss of microvilli are classic reversible ultrastructural changes.',
            explanationC:
              'Correct: Severe membrane disruption and mitochondrial permeability transition are the points of no return in cell injury.',
            explanationD:
              'Mild chromatin clumping from glycolytic lactic acidosis is reversible upon restoration of oxygen.',
            difficulty: 'Medium',
            tags: 'Cell Injury,Apoptosis,Mitochondria',
          },
          {
            questionText:
              'A 51-year-old man with severe gallstone pancreatitis develops hypocalcemia with a positive Chvostek sign. Biopsy of peripancreatic omental tissue shows shadowy outlines of necrotic adipocytes with basophilic deposits on H&E stain. What chemical process accounts for the hypocalcemia and basophilic deposits?',
            optionA: 'Metastatic calcification driven by parathyroid hormone excess',
            optionB: 'Saponification of free fatty acids with calcium ions',
            optionC: 'Denaturation of intracellular albumin by trypsinogen',
            optionD: 'Immune complex deposition in arteriolar walls (fibrinoid necrosis)',
            correctAnswer: 'B',
            explanation:
              'In acute pancreatitis, released pancreatic lipases hydrolyze adipocyte triglycerides into free fatty acids. These negatively charged fatty acids bind extracellular Ca2+ ions in a process called saponification (forming chalky-white calcium soaps that appear basophilic on H&E), consuming serum calcium and causing clinical hypocalcemia.',
            explanationA:
              'Metastatic calcification occurs in normal tissues when serum calcium or phosphate is elevated, whereas saponification is a form of dystrophic calcification in necrotic tissue that lowers serum calcium.',
            explanationB:
              'Correct: Lipase-released fatty acids chelate calcium ions to form insoluble calcium soaps (saponification).',
            explanationC:
              'Protein denaturation characterizes coagulative necrosis, not fat necrosis.',
            explanationD:
              'Fibrinoid necrosis occurs in malignant hypertension and polyarteritis nodosa.',
            difficulty: 'Medium',
            tags: 'Necrosis,Pancreatitis,Calcification',
          },
        ],
      },
    ],
  },
  {
    slug: 'clinical-pharmacology',
    title: 'Clinical Pharmacology',
    description:
      'Receptor signal transduction, autonomic nervous system pharmacology, and clinical toxicology.',
    displayOrder: 4,
    lectures: [
      {
        title: 'Autonomic Nervous System Cholinoceptor & Adrenoceptor Pharmacology',
        description:
          'Covers G-protein second messenger cascades (Gq, Gs, Gi), muscarinic agonists/antagonists, cholinesterase inhibitors, and adrenergic receptor selectivity.',
        lectureNumber: 1,
        estimatedMinutes: 35,
        educationalNotes:
          'Autonomic G-Protein Coupled Receptor Summary:\n• Gq (PLC → IP3/DAG → ↑ [Ca2+]i): Alpha-1, M1, M3, H1, V1.\n• Gi (↓ Adenylyl Cyclase → ↓ cAMP): Alpha-2, M2, D2.\n• Gs (↑ Adenylyl Cyclase → ↑ cAMP): Beta-1, Beta-2, Beta-3, D1, H2, V2.\n\nOrganophosphate Poisoning (Parathion, Malathion, Sarin):\n• Irreversibly phosphorylates acetylcholinesterase → cholinergic crisis (DUMBBELLS: Diarrhea, Urination, Miosis, Bronchospasm, Bradycardia, Excitation of skeletal muscle/CNS, Lacrimation, Lethargy, Salivation).\n• Treatment: Atropine (competitive muscarinic antagonist that crosses BBB) + Pralidoxime (2-PAM; regenerates acetylcholinesterase at nicotinic & muscarinic sites if given before "aging").',
        questions: [
          {
            questionText:
              'A 34-year-old agricultural worker is brought to the emergency department with profuse salivation, lacrimation, pinpoint pupils, wheezing, bradycardia, and muscle fasciculations after accidental exposure to parathion insecticide. In addition to high-dose intravenous atropine, the physician administers pralidoxime. Which clinical finding in this patient requires pralidoxime because it is NOT reversed by atropine alone?',
            optionA: 'Bronchoconstriction and copious bronchial secretions',
            optionB: 'Skeletal muscle fasciculations and diaphragmatic weakness',
            optionC: 'Sinus bradycardia and AV nodal block',
            optionD: 'Pupillary miosis and ciliary muscle spasm',
            correctAnswer: 'B',
            explanation:
              'Atropine is a competitive antagonist strictly at muscarinic (M1–M5) acetylcholine receptors and therefore has no effect at nicotinic receptors (NM) on the skeletal muscle neuromuscular junction. Pralidoxime (2-PAM) is required to cleave the organophosphate group from acetylcholinesterase before "aging" occurs, restoring enzyme activity at both muscarinic and nicotinic synapses and reversing neuromuscular blockade and fasciculations.',
            explanationA:
              'Bronchoconstriction and bronchial gland secretion are mediated by M3 muscarinic receptors and are reversed by atropine.',
            explanationB:
              'Correct: Skeletal muscle fasciculations and paralysis are mediated by nicotinic (NM) receptors at the neuromuscular junction, which atropine cannot block.',
            explanationC:
              'Bradycardia is mediated by cardiac M2 muscarinic receptors and responds to atropine.',
            explanationD:
              'Miosis is mediated by M3 muscarinic receptors on the iris sphincter muscle and responds to atropine.',
            difficulty: 'Medium',
            tags: 'Autonomic Pharmacology,Cholinergics,Toxicology',
          },
          {
            questionText:
              'Activation of which autonomic receptor subtype stimulates phospholipase C ( via a Gq protein) to cleave PIP2 into inositol 1,4,5-trisphosphate (IP3) and diacylglycerol (DAG)?',
            optionA: 'Cardiac M2 muscarinic receptor',
            optionB: 'Bronchial smooth muscle Beta-2 adrenoceptor',
            optionC: 'Vascular smooth muscle Alpha-1 adrenoceptor',
            optionD: 'Presynaptic Alpha-2 adrenoceptor',
            correctAnswer: 'C',
            explanation:
              'Alpha-1 adrenoceptors (along with M1 and M3 muscarinic receptors) couple to Gq heterotrimeric G-proteins, activating phospholipase C to generate IP3 (which releases Ca2+ from the sarcoplasmic reticulum) and DAG (which activates protein kinase C), producing vascular smooth muscle vasoconstriction.',
            explanationA:
              'Cardiac M2 receptors couple to Gi, inhibiting adenylyl cyclase and opening G-protein-gated inward rectifier K+ channels (GIRK).',
            explanationB:
              'Beta-2 adrenoceptors couple to Gs, increasing intracellular cAMP to relax bronchial smooth muscle.',
            explanationC:
              'Correct: Alpha-1 receptors are Gq-coupled and raise intracellular Ca2+ via IP3.',
            explanationD:
              'Alpha-2 adrenoceptors couple to Gi, reducing presynaptic cAMP and inhibiting norepinephrine release.',
            difficulty: 'Easy',
            tags: 'Signal Transduction,Adrenoceptors,Autonomic Pharmacology',
          },
        ],
      },
    ],
  },
];
