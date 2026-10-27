export type OptionKey = 'A' | 'B' | 'C' | 'D';
export type DifficultyLevel = 'Easy' | 'Medium' | 'Hard';
export type ContentStatus = 'draft' | 'published' | 'archived';
export type PracticeMode = 'study' | 'exam' | 'custom';

export const OPTION_KEYS: OptionKey[] = ['A', 'B', 'C', 'D'];
export const VALID_DIFFICULTIES: DifficultyLevel[] = ['Easy', 'Medium', 'Hard'];
export const VALID_STATUSES: ContentStatus[] = ['draft', 'published', 'archived'];

export interface CanonicalQuestion {
  id: number;
  subjectId: number;
  lectureId: number;
  questionBankId?: number | null;
  subjectTitle?: string;
  lectureTitle?: string;
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
  status: ContentStatus;
  version?: number;
}

export type OptionPermutation = Record<OptionKey, OptionKey>;

/**
 * Deterministic or Math.random PRNG for shuffling
 */
export function createSeededRandom(seed?: number): () => number {
  if (seed === undefined) {
    return () => Math.random();
  }
  let state = seed % 2147483647;
  if (state <= 0) state += 2147483646;
  return () => {
    state = (state * 16807) % 2147483647;
    return (state - 1) / 2147483646;
  };
}

export function shuffleArray<T>(items: readonly T[], seed?: number): T[] {
  const copy = [...items];
  const rand = createSeededRandom(seed);
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const tmp = copy[i];
    copy[i] = copy[j];
    copy[j] = tmp;
  }
  return copy;
}

/**
 * Creates a mapping from displayed option letter ('A'|'B'|'C'|'D')
 * to the underlying canonical option letter ('A'|'B'|'C'|'D').
 */
export function createOptionPermutation(shuffle: boolean, seed?: number): OptionPermutation {
  if (!shuffle) {
    return { A: 'A', B: 'B', C: 'C', D: 'D' };
  }
  const shuffled = shuffleArray(OPTION_KEYS, seed);
  return {
    A: shuffled[0],
    B: shuffled[1],
    C: shuffled[2],
    D: shuffled[3],
  };
}

/**
 * Converts a student's displayed choice ('A'..'D') back to the canonical option key ('A'..'D').
 */
export function resolveCanonicalOption(
  displayedChoice: OptionKey | null | undefined,
  permutation: OptionPermutation
): OptionKey | null {
  if (!displayedChoice || !OPTION_KEYS.includes(displayedChoice)) {
    return null;
  }
  return permutation[displayedChoice] ?? null;
}

/**
 * Finds which displayed option key ('A'..'D') corresponds to a canonical option key ('A'..'D').
 */
export function resolveDisplayedOption(
  canonicalOption: OptionKey | null | undefined,
  permutation: OptionPermutation
): OptionKey | null {
  if (!canonicalOption) return null;
  for (const dispKey of OPTION_KEYS) {
    if (permutation[dispKey] === canonicalOption) {
      return dispKey;
    }
  }
  return null;
}

const ALLOWED_SVG_TAGS: Record<string, string> = {
  svg: 'svg',
  g: 'g',
  path: 'path',
  circle: 'circle',
  ellipse: 'ellipse',
  rect: 'rect',
  line: 'line',
  polyline: 'polyline',
  polygon: 'polygon',
  text: 'text',
  tspan: 'tspan',
  defs: 'defs',
  lineargradient: 'linearGradient',
  radialgradient: 'radialGradient',
  stop: 'stop',
  marker: 'marker',
  clippath: 'clipPath',
  mask: 'mask',
  pattern: 'pattern',
  title: 'title',
  desc: 'desc',
};

const ALLOWED_SVG_ATTRIBUTES: Record<string, string> = {
  id: 'id',
  class: 'class',
  viewbox: 'viewBox',
  preserveaspectratio: 'preserveAspectRatio',
  width: 'width',
  height: 'height',
  x: 'x',
  y: 'y',
  x1: 'x1',
  y1: 'y1',
  x2: 'x2',
  y2: 'y2',
  cx: 'cx',
  cy: 'cy',
  r: 'r',
  rx: 'rx',
  ry: 'ry',
  d: 'd',
  points: 'points',
  fill: 'fill',
  'fill-opacity': 'fill-opacity',
  'fill-rule': 'fill-rule',
  stroke: 'stroke',
  'stroke-width': 'stroke-width',
  'stroke-dasharray': 'stroke-dasharray',
  'stroke-dashoffset': 'stroke-dashoffset',
  'stroke-linecap': 'stroke-linecap',
  'stroke-linejoin': 'stroke-linejoin',
  'stroke-miterlimit': 'stroke-miterlimit',
  'stroke-opacity': 'stroke-opacity',
  opacity: 'opacity',
  transform: 'transform',
  'text-anchor': 'text-anchor',
  'dominant-baseline': 'dominant-baseline',
  'alignment-baseline': 'alignment-baseline',
  'font-family': 'font-family',
  'font-size': 'font-size',
  'font-weight': 'font-weight',
  'font-style': 'font-style',
  'letter-spacing': 'letter-spacing',
  dx: 'dx',
  dy: 'dy',
  offset: 'offset',
  'stop-color': 'stop-color',
  'stop-opacity': 'stop-opacity',
  gradientunits: 'gradientUnits',
  gradienttransform: 'gradientTransform',
  patternunits: 'patternUnits',
  patterntransform: 'patternTransform',
  clippathunits: 'clipPathUnits',
  markerwidth: 'markerWidth',
  markerheight: 'markerHeight',
  markerunits: 'markerUnits',
  refx: 'refX',
  refy: 'refY',
  orient: 'orient',
  'marker-start': 'marker-start',
  'marker-mid': 'marker-mid',
  'marker-end': 'marker-end',
  'clip-path': 'clip-path',
  mask: 'mask',
  'vector-effect': 'vector-effect',
  style: 'style',
  role: 'role',
  'aria-label': 'aria-label',
  'aria-hidden': 'aria-hidden',
};

const SAFE_SVG_STYLE_PROPERTIES = new Set([
  'fill',
  'fill-opacity',
  'fill-rule',
  'stroke',
  'stroke-width',
  'stroke-dasharray',
  'stroke-dashoffset',
  'stroke-linecap',
  'stroke-linejoin',
  'stroke-opacity',
  'opacity',
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'text-anchor',
  'dominant-baseline',
  'letter-spacing',
  'stop-color',
  'stop-opacity',
  'display',
  'visibility',
]);

const NAMED_HTML_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  colon: ':',
  tab: '\t',
  newline: '\n',
  nbsp: ' ',
};

function decodeHtmlEntities(input: string): string {
  let current = input;
  for (let pass = 0; pass < 3; pass++) {
    const decoded = current
      .replace(/&#x([0-9a-f]+);?/gi, (_m, hex) => {
        const code = Number.parseInt(hex, 16);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff
          ? String.fromCodePoint(code)
          : '';
      })
      .replace(/&#([0-9]+);?/g, (_m, dec) => {
        const code = Number.parseInt(dec, 10);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff
          ? String.fromCodePoint(code)
          : '';
      })
      .replace(/&([a-z0-9]+);?/gi, (full, name) => {
        const key = String(name).toLowerCase();
        return key in NAMED_HTML_ENTITIES ? NAMED_HTML_ENTITIES[key] : full;
      });
    if (decoded === current) break;
    current = decoded;
  }
  return current;
}

function escapeXmlText(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function escapeXmlAttr(value: string): string {
  return escapeXmlText(value)
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isSafeSvgAttributeValue(attrName: string, rawValue: string): string | null {
  const decoded = decodeHtmlEntities(rawValue)
    // Remove ASCII control chars and zero-width spaces that could obfuscate schemes
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\ufeff]/g, '')
    .trim();

  if (!decoded) return '';

  if (attrName === 'style') {
    const safeDecls: string[] = [];
    const declarations = decoded.split(';');
    for (const decl of declarations) {
      const trimmedDecl = decl.trim();
      if (!trimmedDecl) continue;
      const colonIdx = trimmedDecl.indexOf(':');
      if (colonIdx <= 0) continue;
      const prop = trimmedDecl.slice(0, colonIdx).trim().toLowerCase();
      const val = trimmedDecl.slice(colonIdx + 1).trim();
      if (!SAFE_SVG_STYLE_PROPERTIES.has(prop)) continue;
      const valLower = val.replace(/\s+/g, '').toLowerCase();
      if (
        valLower.includes('url(') ||
        valLower.includes('expression') ||
        valLower.includes('@import') ||
        valLower.includes('javascript') ||
        valLower.includes('vbscript') ||
        valLower.includes('data:') ||
        val.includes('\\') ||
        val.includes(':') ||
        val.includes('<') ||
        val.includes('>') ||
        !/^[#(),.%a-zA-Z0-9\s_-]+$/.test(val)
      ) {
        continue;
      }
      safeDecls.push(`${prop}: ${val}`);
    }
    return safeDecls.length > 0 ? safeDecls.join('; ') : null;
  }

  const compactLower = decoded.replace(/\s+/g, '').toLowerCase();

  // Block any executable or external URI schemes, expressions, or embedded markup
  if (
    compactLower.includes('javascript:') ||
    compactLower.includes('vbscript:') ||
    compactLower.includes('data:') ||
    compactLower.includes('file:') ||
    compactLower.includes('http:') ||
    compactLower.includes('https:') ||
    compactLower.includes('//') ||
    compactLower.includes('expression(') ||
    compactLower.includes('@import') ||
    compactLower.includes('-moz-binding') ||
    compactLower.includes('behavior:') ||
    decoded.includes('<') ||
    decoded.includes('>')
  ) {
    return null;
  }

  // Only allow local fragment references like url(#gradientId) on attributes that reference defs
  if (compactLower.includes('url(')) {
    if (
      attrName === 'fill' ||
      attrName === 'stroke' ||
      attrName === 'clip-path' ||
      attrName === 'mask' ||
      attrName === 'marker-start' ||
      attrName === 'marker-mid' ||
      attrName === 'marker-end'
    ) {
      if (!/^url\(\s*#[a-zA-Z0-9_-]+\s*\)$/.test(decoded)) {
        return null;
      }
    } else {
      return null;
    }
  }

  return decoded;
}

interface ParsedSvgAttribute {
  name: string;
  value: string;
}

function parseTagAttributes(attrSource: string): ParsedSvgAttribute[] {
  const attrs: ParsedSvgAttribute[] = [];
  let i = 0;
  const len = attrSource.length;

  while (i < len) {
    while (i < len && /[\s/]/.test(attrSource[i])) i++;
    if (i >= len) break;

    const nameStart = i;
    while (i < len && !/[\s=/>"'`]/.test(attrSource[i])) i++;
    const rawName = attrSource.slice(nameStart, i).trim().toLowerCase();
    if (!rawName) {
      i++;
      continue;
    }

    while (i < len && /\s/.test(attrSource[i])) i++;

    let rawValue = '';
    if (i < len && attrSource[i] === '=') {
      i++; // skip '='
      while (i < len && /\s/.test(attrSource[i])) i++;
      if (i < len) {
        const quote = attrSource[i];
        if (quote === '"' || quote === "'") {
          i++;
          const valStart = i;
          while (i < len && attrSource[i] !== quote) i++;
          rawValue = attrSource.slice(valStart, i);
          if (i < len && attrSource[i] === quote) i++;
        } else {
          const valStart = i;
          while (i < len && !/[\s/>]/.test(attrSource[i])) i++;
          rawValue = attrSource.slice(valStart, i);
        }
      }
    }

    attrs.push({ name: rawName, value: rawValue });
  }

  return attrs;
}

interface SvgAstNode {
  tag: string;
  attrs: Array<{ name: string; value: string }>;
  children: Array<SvgAstNode | string>;
}

/**
 * Strict parser-based allowlist sanitizer for medical SVG diagrams.
 * Parses XML/SVG markup into an explicit AST, strips all non-allowlisted elements (and their subtrees)
 * such as <script>, <foreignObject>, <iframe>, <style>, <a>, <image>, <use>, and animation tags,
 * strips all event handlers, decodes entities before validating attributes and CSS properties,
 * and serializes canonical SVG markup.
 */
export function sanitizeSvgDiagram(rawSvg: string | null | undefined): string {
  if (!rawSvg || typeof rawSvg !== 'string') return '';
  const trimmed = rawSvg.trim();
  if (!trimmed) return '';

  // Remove XML comments, CDATA, processing instructions, and DOCTYPE declarations before tokenizing
  const cleanedSource = trimmed
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/gi, '')
    .replace(/<\?[\s\S]*?\?>/g, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '')
    .replace(/<![a-zA-Z][\s\S]*?>/g, '');

  const rootChildren: Array<SvgAstNode | string> = [];
  const stack: SvgAstNode[] = [];
  let ignoredDepth = 0;

  let cursor = 0;
  const totalLen = cleanedSource.length;

  while (cursor < totalLen) {
    const tagStart = cleanedSource.indexOf('<', cursor);
    const textSliceEnd = tagStart === -1 ? totalLen : tagStart;
    const textBefore = cleanedSource.slice(cursor, textSliceEnd);

    if (ignoredDepth === 0 && stack.length > 0 && textBefore) {
      const parentTag = stack[stack.length - 1].tag;
      if (
        parentTag === 'text' ||
        parentTag === 'tspan' ||
        parentTag === 'title' ||
        parentTag === 'desc'
      ) {
        const cleanText = decodeHtmlEntities(textBefore);
        if (cleanText) {
          stack[stack.length - 1].children.push(cleanText);
        }
      }
    }

    if (tagStart === -1) break;

    // Scan to closing '>' while respecting single and double quotes
    let scan = tagStart + 1;
    let activeQuote: string | null = null;
    while (scan < totalLen) {
      const ch = cleanedSource[scan];
      if (activeQuote) {
        if (ch === activeQuote) {
          activeQuote = null;
        }
      } else {
        if (ch === '"' || ch === "'") {
          activeQuote = ch;
        } else if (ch === '>') {
          break;
        }
      }
      scan++;
    }

    if (scan >= totalLen) {
      // Unclosed '<' at end of input — drop it
      break;
    }

    const insideTag = cleanedSource.slice(tagStart + 1, scan).trim();
    cursor = scan + 1;

    if (!insideTag) continue;

    const isClosing = insideTag.startsWith('/');
    const bodyAfterLeadingSlash = isClosing ? insideTag.slice(1).trim() : insideTag;
    const isSelfClosing = !isClosing && bodyAfterLeadingSlash.endsWith('/');
    const bodyCore = isSelfClosing
      ? bodyAfterLeadingSlash.slice(0, -1).trim()
      : bodyAfterLeadingSlash;

    const nameMatch = /^([a-zA-Z0-9:_-]+)([\s\S]*)$/.exec(bodyCore);
    if (!nameMatch) continue;

    const rawTagName = nameMatch[1];
    const rawAttrChunk = nameMatch[2] || '';
    const lowerTagName = rawTagName.toLowerCase();

    if (isClosing) {
      if (ignoredDepth > 0) {
        ignoredDepth--;
        continue;
      }
      const canonicalClosing = ALLOWED_SVG_TAGS[lowerTagName];
      if (!canonicalClosing) continue;
      for (let s = stack.length - 1; s >= 0; s--) {
        if (stack[s].tag === canonicalClosing) {
          stack.length = s;
          break;
        }
      }
      continue;
    }

    if (ignoredDepth > 0) {
      if (!isSelfClosing) {
        ignoredDepth++;
      }
      continue;
    }

    const canonicalTag = ALLOWED_SVG_TAGS[lowerTagName];
    if (!canonicalTag) {
      // Disallowed element (e.g., script, foreignObject, iframe, style, a, image, animate):
      // drop the element and ignore everything inside its subtree
      if (!isSelfClosing) {
        ignoredDepth = 1;
      }
      continue;
    }

    const parsedAttrs = parseTagAttributes(rawAttrChunk);
    const safeAttrs: Array<{ name: string; value: string }> = [];
    const seenAttrNames = new Set<string>();

    if (canonicalTag === 'svg') {
      safeAttrs.push({ name: 'xmlns', value: 'http://www.w3.org/2000/svg' });
      seenAttrNames.add('xmlns');
    }

    for (const attr of parsedAttrs) {
      const attrLower = attr.name.toLowerCase();
      // Strictly reject all event handlers (on*) and namespace declarations/prefixes (xmlns:*, xlink:*)
      if (attrLower.startsWith('on') || attrLower.includes(':')) {
        continue;
      }
      if (attrLower === 'xmlns') {
        continue;
      }
      const canonicalAttrName = ALLOWED_SVG_ATTRIBUTES[attrLower];
      if (!canonicalAttrName || seenAttrNames.has(canonicalAttrName)) {
        continue;
      }
      const validatedValue = isSafeSvgAttributeValue(attrLower, attr.value);
      if (validatedValue === null) {
        continue;
      }
      seenAttrNames.add(canonicalAttrName);
      safeAttrs.push({ name: canonicalAttrName, value: validatedValue });
    }

    const node: SvgAstNode = {
      tag: canonicalTag,
      attrs: safeAttrs,
      children: [],
    };

    if (stack.length > 0) {
      stack[stack.length - 1].children.push(node);
    } else if (canonicalTag === 'svg') {
      rootChildren.push(node);
    } else {
      // Ignore top-level fragments that are not inside an <svg> root
      continue;
    }

    if (!isSelfClosing) {
      stack.push(node);
    }
  }

  const firstSvg = rootChildren.find(
    (child): child is SvgAstNode => typeof child !== 'string' && child.tag === 'svg'
  );
  if (!firstSvg) {
    return '';
  }

  function serializeNode(node: SvgAstNode): string {
    const attrStr = node.attrs
      .map((a) => ` ${a.name}="${escapeXmlAttr(a.value)}"`)
      .join('');
    if (node.children.length === 0) {
      return `<${node.tag}${attrStr}></${node.tag}>`;
    }
    const inner = node.children
      .map((child) =>
        typeof child === 'string' ? escapeXmlText(child) : serializeNode(child)
      )
      .join('');
    return `<${node.tag}${attrStr}>${inner}</${node.tag}>`;
  }

  return serializeNode(firstSvg);
}

/**
 * Formats question options according to the option permutation.
 * During active Exam Mode (hideAnswers = true), strips correctAnswer and all explanations
 * so the browser cannot inspect them in network payloads or DOM state.
 */
export function formatQuestionForClient(
  question: CanonicalQuestion,
  permutation: OptionPermutation,
  hideAnswers: boolean
) {
  const canonicalOptions: Record<OptionKey, string> = {
    A: question.optionA,
    B: question.optionB,
    C: question.optionC,
    D: question.optionD,
  };

  const canonicalExplanations: Record<OptionKey, string> = {
    A: question.explanationA,
    B: question.explanationB,
    C: question.explanationC,
    D: question.explanationD,
  };

  const displayedOptions: Record<OptionKey, string> = {
    A: canonicalOptions[permutation.A],
    B: canonicalOptions[permutation.B],
    C: canonicalOptions[permutation.C],
    D: canonicalOptions[permutation.D],
  };

  const safeDiagramSvg = sanitizeSvgDiagram(question.diagramSvg);

  if (hideAnswers) {
    return {
      id: question.id,
      subjectId: question.subjectId,
      lectureId: question.lectureId,
      subjectTitle: question.subjectTitle,
      lectureTitle: question.lectureTitle,
      questionText: question.questionText,
      options: displayedOptions,
      difficulty: question.difficulty,
      tags: question.tags,
      diagramSvg: safeDiagramSvg,
      permutation,
    };
  }

  const displayedExplanations: Record<OptionKey, string> = {
    A: canonicalExplanations[permutation.A],
    B: canonicalExplanations[permutation.B],
    C: canonicalExplanations[permutation.C],
    D: canonicalExplanations[permutation.D],
  };

  return {
    id: question.id,
    subjectId: question.subjectId,
    lectureId: question.lectureId,
    subjectTitle: question.subjectTitle,
    lectureTitle: question.lectureTitle,
    questionText: question.questionText,
    options: displayedOptions,
    correctDisplayedOption: resolveDisplayedOption(question.correctAnswer, permutation),
    correctCanonicalOption: question.correctAnswer,
    explanation: question.explanation,
    optionExplanations: displayedExplanations,
    difficulty: question.difficulty,
    tags: question.tags,
    diagramSvg: safeDiagramSvg,
    permutation,
  };
}

export interface ScoreResult {
  totalQuestions: number;
  correctCount: number;
  incorrectCount: number;
  unansweredCount: number;
  exactRatio: number; // 0..1 exact floating ratio
  scorePercentage: number; // integer 0..100 for display only
  questionResults: Array<{
    questionId: number;
    selectedCanonical: OptionKey | null;
    correctCanonical: OptionKey;
    isCorrect: boolean;
    isUnanswered: boolean;
  }>;
}

/**
 * Scores an exam or study session using exact counts (never derived from rounded percentages).
 */
export function scoreExamSession(
  questions: Array<{ id: number; correctAnswer: OptionKey }>,
  canonicalAnswers: Record<number, OptionKey | null | undefined>
): ScoreResult {
  const totalQuestions = questions.length;
  if (totalQuestions === 0) {
    return {
      totalQuestions: 0,
      correctCount: 0,
      incorrectCount: 0,
      unansweredCount: 0,
      exactRatio: 0,
      scorePercentage: 0,
      questionResults: [],
    };
  }

  let correctCount = 0;
  let incorrectCount = 0;
  let unansweredCount = 0;
  const questionResults: ScoreResult['questionResults'] = [];

  for (const q of questions) {
    const rawSelection = canonicalAnswers[q.id] ?? null;
    const selectedCanonical =
      rawSelection && OPTION_KEYS.includes(rawSelection) ? rawSelection : null;

    if (selectedCanonical === null) {
      unansweredCount++;
      questionResults.push({
        questionId: q.id,
        selectedCanonical: null,
        correctCanonical: q.correctAnswer,
        isCorrect: false,
        isUnanswered: true,
      });
    } else if (selectedCanonical === q.correctAnswer) {
      correctCount++;
      questionResults.push({
        questionId: q.id,
        selectedCanonical,
        correctCanonical: q.correctAnswer,
        isCorrect: true,
        isUnanswered: false,
      });
    } else {
      incorrectCount++;
      questionResults.push({
        questionId: q.id,
        selectedCanonical,
        correctCanonical: q.correctAnswer,
        isCorrect: false,
        isUnanswered: false,
      });
    }
  }

  const exactRatio = correctCount / totalQuestions;
  const scorePercentage = Math.round(exactRatio * 100);

  return {
    totalQuestions,
    correctCount,
    incorrectCount,
    unansweredCount,
    exactRatio,
    scorePercentage,
    questionResults,
  };
}

export interface QuestionSelectionCriteria {
  subjectIds?: number[];
  lectureIds?: number[];
  difficulties?: DifficultyLevel[];
  tagFilter?: string;
  requestedCount?: number;
  shuffleQuestions?: boolean;
  recentlyAnsweredIds?: Set<number>;
  seed?: number;
}

export interface QuestionSelectionResult<T extends { id: number }> {
  selectedQuestions: T[];
  totalAvailable: number;
  requestedCount: number;
  shortfallNotice: string | null;
}

/**
 * Selects questions matching filters, prioritizing unseen/non-recent questions when enough alternatives exist,
 * and never silently duplicating questions when requestedCount > totalAvailable.
 */
export function selectPracticeQuestions<
  T extends {
    id: number;
    subjectId: number;
    lectureId: number;
    difficulty: string;
    tags: string;
    status: string;
  }
>(pool: T[], criteria: QuestionSelectionCriteria): QuestionSelectionResult<T> {
  let eligible = pool.filter((q) => q.status === 'published');

  if (criteria.subjectIds && criteria.subjectIds.length > 0) {
    const subjSet = new Set(criteria.subjectIds);
    eligible = eligible.filter((q) => subjSet.has(q.subjectId));
  }

  if (criteria.lectureIds && criteria.lectureIds.length > 0) {
    const lectSet = new Set(criteria.lectureIds);
    eligible = eligible.filter((q) => lectSet.has(q.lectureId));
  }

  if (criteria.difficulties && criteria.difficulties.length > 0) {
    const diffSet = new Set<string>(criteria.difficulties);
    eligible = eligible.filter((q) => diffSet.has(q.difficulty));
  }

  if (criteria.tagFilter && criteria.tagFilter.trim() !== '') {
    const needle = criteria.tagFilter.trim().toLowerCase();
    eligible = eligible.filter((q) =>
      q.tags
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .some((t) => t.includes(needle))
    );
  }

  const totalAvailable = eligible.length;
  const requestedCount = criteria.requestedCount ?? totalAvailable;

  let orderedPool = eligible;
  if (criteria.shuffleQuestions) {
    orderedPool = shuffleArray(eligible, criteria.seed);
  }

  if (criteria.recentlyAnsweredIds && criteria.recentlyAnsweredIds.size > 0) {
    const fresh = orderedPool.filter((q) => !criteria.recentlyAnsweredIds!.has(q.id));
    const recent = orderedPool.filter((q) => criteria.recentlyAnsweredIds!.has(q.id));
    orderedPool = [...fresh, ...recent];
  }

  const selectedQuestions = orderedPool.slice(0, Math.min(requestedCount, totalAvailable));
  let shortfallNotice: string | null = null;

  if (totalAvailable === 0) {
    shortfallNotice = 'No published questions match your selected filters.';
  } else if (requestedCount > totalAvailable) {
    shortfallNotice = `Requested ${requestedCount} questions, but only ${totalAvailable} unique published questions match your filters. Loaded all ${totalAvailable} available questions without duplicates.`;
  }

  return {
    selectedQuestions,
    totalAvailable,
    requestedCount,
    shortfallNotice,
  };
}

export interface TopicPerformanceMetric {
  topic: string;
  totalAttempts: number;
  uniqueQuestionsAttempted: number;
  correctAttempts: number;
  accuracyPercentage: number;
  isSmallSample: boolean;
  classification: 'Needs Review' | 'Developing' | 'Strong' | 'Insufficient Sample';
}

/**
 * Calculates topic-level performance and explicitly guards against labeling a student
 * weak based on only 1 or 2 questions (marks isSmallSample = true and classification = 'Insufficient Sample' when < 3).
 */
export function computeTopicPerformance(
  attempts: Array<{
    questionId: number | null;
    isCorrect: boolean;
    tags: string;
  }>
): TopicPerformanceMetric[] {
  const map = new Map<
    string,
    { total: number; correct: number; uniqueQuestionIds: Set<number> }
  >();

  for (const att of attempts) {
    const rawTags = att.tags
      ? att.tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
      : ['General Medical Concepts'];
    const tags = rawTags.length > 0 ? rawTags : ['General Medical Concepts'];

    for (const tag of tags) {
      const entry = map.get(tag) ?? {
        total: 0,
        correct: 0,
        uniqueQuestionIds: new Set<number>(),
      };
      entry.total += 1;
      if (att.isCorrect) entry.correct += 1;
      if (att.questionId !== null) entry.uniqueQuestionIds.add(att.questionId);
      map.set(tag, entry);
    }
  }

  const metrics: TopicPerformanceMetric[] = [];
  for (const [topic, stats] of map.entries()) {
    const accuracyPercentage =
      stats.total > 0 ? Math.round((stats.correct / stats.total) * 100) : 0;
    const isSmallSample = stats.total < 3;
    let classification: TopicPerformanceMetric['classification'];
    if (isSmallSample) {
      classification = 'Insufficient Sample';
    } else if (accuracyPercentage < 65) {
      classification = 'Needs Review';
    } else if (accuracyPercentage < 80) {
      classification = 'Developing';
    } else {
      classification = 'Strong';
    }

    metrics.push({
      topic,
      totalAttempts: stats.total,
      uniqueQuestionsAttempted: stats.uniqueQuestionIds.size,
      correctAttempts: stats.correct,
      accuracyPercentage,
      isSmallSample,
      classification,
    });
  }

  return metrics.sort((a, b) => a.accuracyPercentage - b.accuracyPercentage);
}

/**
 * Simple deterministic string hash for duplicate question & CSV file detection
 */
export function computeContentHash(input: string): string {
  const normalized = input.trim().toLowerCase().replace(/\s+/g, ' ');
  let h1 = 0xdeadbeef ^ normalized.length;
  let h2 = 0x41c6ce57 ^ normalized.length;
  for (let i = 0, ch; i < normalized.length; i++) {
    ch = normalized.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}

/**
 * RFC-4180 compliant CSV parser supporting quoted fields, commas, and newlines inside quotes.
 */
export function parseCsvRows(csvText: string): string[][] {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let inQuotes = false;

  const text = csvText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        currentField += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        currentField += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        currentRow.push(currentField.trim());
        currentField = '';
      } else if (ch === '\n') {
        currentRow.push(currentField.trim());
        if (currentRow.some((cell) => cell !== '')) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
      } else {
        currentField += ch;
      }
    }
  }

  currentRow.push(currentField.trim());
  if (currentRow.some((cell) => cell !== '')) {
    rows.push(currentRow);
  }

  return rows;
}

export interface ParsedCsvQuestionRow {
  rowNumber: number;
  subject: string;
  lecture: string;
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
  status: ContentStatus;
  contentHash: string;
  isValid: boolean;
  isDuplicate: boolean;
  errors: string[];
}

export interface CsvValidationReport {
  fileHash: string;
  totalRows: number;
  validCount: number;
  duplicateCount: number;
  invalidCount: number;
  rows: ParsedCsvQuestionRow[];
  headerErrors: string[];
}

export const REQUIRED_CSV_COLUMNS = [
  'subject',
  'lecture',
  'question_text',
  'option_a',
  'option_b',
  'option_c',
  'option_d',
  'correct_answer',
  'explanation',
  'explanation_a',
  'explanation_b',
  'explanation_c',
  'explanation_d',
  'difficulty',
  'tags',
  'status',
] as const;

export function parseAndValidateCsvQuestions(
  csvContent: string,
  existingQuestionHashes: Set<string> = new Set()
): CsvValidationReport {
  const fileHash = computeContentHash(csvContent);
  const rawRows = parseCsvRows(csvContent);

  if (rawRows.length === 0) {
    return {
      fileHash,
      totalRows: 0,
      validCount: 0,
      duplicateCount: 0,
      invalidCount: 0,
      rows: [],
      headerErrors: ['The uploaded CSV file is empty.'],
    };
  }

  const headerRow = rawRows[0].map((h) => h.toLowerCase().trim());
  const headerMap = new Map<string, number>();
  headerRow.forEach((col, idx) => headerMap.set(col, idx));

  const missingHeaders = [
    'subject',
    'lecture',
    'question_text',
    'option_a',
    'option_b',
    'option_c',
    'option_d',
    'correct_answer',
    'explanation',
  ].filter((req) => !headerMap.has(req));

  if (missingHeaders.length > 0) {
    return {
      fileHash,
      totalRows: 0,
      validCount: 0,
      duplicateCount: 0,
      invalidCount: 0,
      rows: [],
      headerErrors: [
        `Missing required CSV columns: ${missingHeaders.join(', ')}. Please download and use the official CSV template.`,
      ],
    };
  }

  const seenHashesInFile = new Set<string>();
  const parsedRows: ParsedCsvQuestionRow[] = [];
  let validCount = 0;
  let duplicateCount = 0;
  let invalidCount = 0;

  const getCol = (row: string[], name: string): string => {
    const idx = headerMap.get(name);
    if (idx === undefined || idx >= row.length) return '';
    return row[idx]?.trim() ?? '';
  };

  for (let i = 1; i < rawRows.length; i++) {
    const raw = rawRows[i];
    const rowNumber = i + 1;
    const errors: string[] = [];

    const subject = getCol(raw, 'subject');
    const lecture = getCol(raw, 'lecture');
    const questionText = getCol(raw, 'question_text');
    const optionA = getCol(raw, 'option_a');
    const optionB = getCol(raw, 'option_b');
    const optionC = getCol(raw, 'option_c');
    const optionD = getCol(raw, 'option_d');
    const rawCorrect = getCol(raw, 'correct_answer').toUpperCase();
    const explanation = getCol(raw, 'explanation');
    const explanationA = getCol(raw, 'explanation_a');
    const explanationB = getCol(raw, 'explanation_b');
    const explanationC = getCol(raw, 'explanation_c');
    const explanationD = getCol(raw, 'explanation_d');
    const rawDifficulty = getCol(raw, 'difficulty') || 'Medium';
    const tags = getCol(raw, 'tags');
    const rawStatus = (getCol(raw, 'status') || 'published').toLowerCase();

    if (!subject) errors.push('Missing subject name.');
    if (!lecture) errors.push('Missing lecture title.');
    if (!questionText || questionText.length < 10) {
      errors.push('Question text is empty or shorter than 10 characters.');
    }
    if (!optionA || !optionB || !optionC || !optionD) {
      errors.push('All four options (option_a, option_b, option_c, option_d) are required.');
    }
    const uniqueOptions = new Set([
      optionA.toLowerCase(),
      optionB.toLowerCase(),
      optionC.toLowerCase(),
      optionD.toLowerCase(),
    ]);
    if (optionA && optionB && optionC && optionD && uniqueOptions.size < 4) {
      errors.push('Options A, B, C, and D must be distinct.');
    }

    if (!OPTION_KEYS.includes(rawCorrect as OptionKey)) {
      errors.push(`Invalid correct_answer "${rawCorrect}". Must be A, B, C, or D.`);
    }

    if (!explanation) {
      errors.push('Explanation for the correct answer is required.');
    }

    const normalizedDifficulty =
      rawDifficulty.charAt(0).toUpperCase() + rawDifficulty.slice(1).toLowerCase();
    if (!VALID_DIFFICULTIES.includes(normalizedDifficulty as DifficultyLevel)) {
      errors.push(
        `Invalid difficulty "${rawDifficulty}". Must be Easy, Medium, or Hard.`
      );
    }

    if (!VALID_STATUSES.includes(rawStatus as ContentStatus)) {
      errors.push(
        `Invalid status "${rawStatus}". Must be published, draft, or archived.`
      );
    }

    const contentHash = computeContentHash(
      `${subject}|${lecture}|${questionText}|${optionA}|${optionB}|${optionC}|${optionD}`
    );

    let isDuplicate = false;
    if (seenHashesInFile.has(contentHash)) {
      isDuplicate = true;
      errors.push('Duplicate question row detected within the same CSV file.');
    } else if (existingQuestionHashes.has(contentHash)) {
      isDuplicate = true;
      errors.push('Question already exists in the database question bank.');
    }
    seenHashesInFile.add(contentHash);

    const isValid = errors.length === 0 && !isDuplicate;
    if (isValid) {
      validCount++;
    } else if (isDuplicate && errors.length === 1) {
      duplicateCount++;
    } else {
      invalidCount++;
    }

    parsedRows.push({
      rowNumber,
      subject,
      lecture,
      questionText,
      optionA,
      optionB,
      optionC,
      optionD,
      correctAnswer: (OPTION_KEYS.includes(rawCorrect as OptionKey)
        ? rawCorrect
        : 'A') as OptionKey,
      explanation,
      explanationA,
      explanationB,
      explanationC,
      explanationD,
      difficulty: (VALID_DIFFICULTIES.includes(normalizedDifficulty as DifficultyLevel)
        ? normalizedDifficulty
        : 'Medium') as DifficultyLevel,
      tags,
      status: (VALID_STATUSES.includes(rawStatus as ContentStatus)
        ? rawStatus
        : 'published') as ContentStatus,
      contentHash,
      isValid,
      isDuplicate,
      errors,
    });
  }

  return {
    fileHash,
    totalRows: parsedRows.length,
    validCount,
    duplicateCount,
    invalidCount,
    rows: parsedRows,
    headerErrors: [],
  };
}

export function getSampleCsvTemplate(): string {
  const header = REQUIRED_CSV_COLUMNS.join(',');
  const sampleRow1 = [
    '"Histology & Cell Biology"',
    '"Eukaryotic Cell Ultrastructure & Membrane Transport"',
    '"A 24-year-old medical student examines an electron micrograph of a pancreatic acinar cell. Which organelle is primarily responsible for O-linked glycosylation and sorting of secretory zymogen proteins?"',
    '"Rough endoplasmic reticulum"',
    '"Golgi apparatus"',
    '"Peroxisome"',
    '"Smooth endoplasmic reticulum"',
    '"B"',
    '"The Golgi apparatus modifies N-linked oligosaccharides, performs O-linked glycosylation on serine/threonine residues, and sorts proteins for secretion or lysosomal targeting."',
    '"RER performs initial N-linked glycosylation on asparagine residues, not O-linked glycosylation."',
    '"Correct: The cis-, medial-, and trans-Golgi cisternae catalyze O-linked glycosylation and package zymogen granules."',
    '"Peroxisomes perform beta-oxidation of very-long-chain fatty acids and hydrogen peroxide degradation."',
    '"SER synthesizes steroid hormones and detoxifies lipid-soluble drugs via cytochrome P450."',
    '"Medium"',
    '"Organelles,Protein Trafficking,Cell Biology"',
    '"published"',
  ].join(',');

  const sampleRow2 = [
    '"Medical Physiology"',
    '"Cardiac Action Potentials & Hemodynamics"',
    '"During Phase 0 of the sinoatrial (SA) nodal action potential, which ion current is primarily responsible for membrane depolarization?"',
    '"Fast voltage-gated Na+ influx (INa)"',
    '"L-type voltage-gated Ca2+ influx (ICa-L)"',
    '"Delayed rectifier K+ efflux (IK)"',
    '"Hyperpolarization-activated pacemaker current (If)"',
    '"B"',
    '"Unlike ventricular myocytes, SA and AV nodal cells lack fast Na+ channels during Phase 0 and instead depolarize via slow L-type Ca2+ channels (ICa-L)."',
    '"Fast Na+ influx drives Phase 0 in atrial, ventricular, and Purkinje fibers, not pacemaker nodal cells."',
    '"Correct: Opening of L-type Ca2+ channels around -40 mV produces the characteristic slow upstroke of Phase 0 in nodal tissue."',
    '"Delayed rectifier K+ efflux mediates Phase 3 repolarization."',
    '"Funny current (If) mediates slow spontaneous depolarization during Phase 4."',
    '"Easy"',
    '"Electrophysiology,SA Node,Cardiovascular"',
    '"published"',
  ].join(',');

  return `${header}\n${sampleRow1}\n${sampleRow2}\n`;
}
