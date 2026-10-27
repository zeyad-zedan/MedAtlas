import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createOptionPermutation,
  resolveCanonicalOption,
  resolveDisplayedOption,
  formatQuestionForClient,
  scoreExamSession,
  selectPracticeQuestions,
  computeTopicPerformance,
  parseAndValidateCsvQuestions,
  getSampleCsvTemplate,
  CanonicalQuestion,
} from './mcq-engine';

const SAMPLE_QUESTION: CanonicalQuestion = {
  id: 101,
  subjectId: 1,
  lectureId: 10,
  questionText: 'Which collagen type forms the basement membrane rete ridges and is defective in Alport syndrome?',
  optionA: 'Type I collagen',
  optionB: 'Type II collagen',
  optionC: 'Type III collagen',
  optionD: 'Type IV collagen',
  correctAnswer: 'D',
  explanation: 'Type IV collagen forms the basal lamina network and is mutated in Alport syndrome.',
  explanationA: 'Type I is found in bone, skin, and tendon.',
  explanationB: 'Type II is found in hyaline cartilage and vitreous humor.',
  explanationC: 'Type III forms reticular fibers in blood vessels.',
  explanationD: 'Correct: Type IV collagen forms basement membranes.',
  difficulty: 'Medium',
  tags: 'Collagen,Extracellular Matrix',
  status: 'published',
};

test('MCQ scoring calculates correct, incorrect, unanswered, and percentage without rounding distortion', () => {
  const questions = [
    { id: 1, correctAnswer: 'A' as const },
    { id: 2, correctAnswer: 'B' as const },
    { id: 3, correctAnswer: 'C' as const },
  ];

  const result = scoreExamSession(questions, {
    1: 'A', // correct
    2: 'D', // incorrect
    3: null, // unanswered
  });

  assert.equal(result.totalQuestions, 3);
  assert.equal(result.correctCount, 1);
  assert.equal(result.incorrectCount, 1);
  assert.equal(result.unansweredCount, 1);
  assert.equal(result.exactRatio, 1 / 3);
  assert.equal(result.scorePercentage, 33);
});

test('Empty exam session handles zero questions cleanly without NaN', () => {
  const result = scoreExamSession([], {});
  assert.equal(result.totalQuestions, 0);
  assert.equal(result.correctCount, 0);
  assert.equal(result.scorePercentage, 0);
  assert.equal(result.exactRatio, 0);
});

test('Option shuffling preserves the association with the canonical correct answer', () => {
  for (let seed = 1; seed <= 20; seed++) {
    const perm = createOptionPermutation(true, seed);
    const formatted = formatQuestionForClient(SAMPLE_QUESTION, perm, false);
    const displayedCorrect = formatted.correctDisplayedOption;
    assert.ok(displayedCorrect, 'Displayed correct option must be defined');

    // The text at displayedCorrect must match the original correct option D ('Type IV collagen')
    assert.equal(formatted.options[displayedCorrect!], 'Type IV collagen');

    // When the student selects displayedCorrect, resolving back to canonical must yield 'D'
    const resolvedCanonical = resolveCanonicalOption(displayedCorrect, perm);
    assert.equal(resolvedCanonical, 'D');
    assert.equal(resolveDisplayedOption('D', perm), displayedCorrect);
  }
});

test('Active exam mode strips correct answers and explanations from client payload', () => {
  const perm = createOptionPermutation(true, 42);
  const hiddenPayload = formatQuestionForClient(SAMPLE_QUESTION, perm, true) as Record<string, unknown>;

  assert.equal('correctDisplayedOption' in hiddenPayload, false);
  assert.equal('correctCanonicalOption' in hiddenPayload, false);
  assert.equal('explanation' in hiddenPayload, false);
  assert.equal('optionExplanations' in hiddenPayload, false);
  assert.equal(typeof hiddenPayload.options, 'object');
});

test('Question selection respects requested count, filters unpublished content, and explains shortfalls without duplicating', () => {
  const pool = [
    { id: 1, subjectId: 1, lectureId: 10, difficulty: 'Easy', tags: 'Cell', status: 'published' },
    { id: 2, subjectId: 1, lectureId: 10, difficulty: 'Medium', tags: 'Cell', status: 'published' },
    { id: 3, subjectId: 1, lectureId: 10, difficulty: 'Hard', tags: 'Membrane', status: 'published' },
    { id: 4, subjectId: 1, lectureId: 10, difficulty: 'Easy', tags: 'Cell', status: 'draft' }, // unpublished must be excluded
  ];

  const subset = selectPracticeQuestions(pool, {
    subjectIds: [1],
    requestedCount: 2,
    shuffleQuestions: true,
    seed: 7,
  });
  assert.equal(subset.selectedQuestions.length, 2);
  assert.equal(subset.totalAvailable, 3);
  assert.equal(subset.shortfallNotice, null);

  const overRequest = selectPracticeQuestions(pool, {
    subjectIds: [1],
    requestedCount: 10,
  });
  assert.equal(overRequest.selectedQuestions.length, 3);
  assert.ok(overRequest.shortfallNotice?.includes('only 3 unique published questions'));
});

test('Weak-topic analysis does not label student weak on only 1 or 2 attempts without small-sample notice', () => {
  const attempts = [
    { questionId: 1, isCorrect: false, tags: 'Rare Enzyme Defect' },
    { questionId: 2, isCorrect: false, tags: 'Rare Enzyme Defect' },
    { questionId: 3, isCorrect: false, tags: 'Cardiac Action Potential' },
    { questionId: 4, isCorrect: false, tags: 'Cardiac Action Potential' },
    { questionId: 5, isCorrect: true, tags: 'Cardiac Action Potential' },
  ];

  const metrics = computeTopicPerformance(attempts);
  const rareTopic = metrics.find((m) => m.topic === 'Rare Enzyme Defect')!;
  const cardiacTopic = metrics.find((m) => m.topic === 'Cardiac Action Potential')!;

  assert.equal(rareTopic.totalAttempts, 2);
  assert.equal(rareTopic.isSmallSample, true);
  assert.equal(rareTopic.classification, 'Insufficient Sample');

  assert.equal(cardiacTopic.totalAttempts, 3);
  assert.equal(cardiacTopic.isSmallSample, false);
  assert.equal(cardiacTopic.classification, 'Needs Review');
});

test('CSV bulk import validator accepts valid template rows and flags invalid or duplicate rows clearly', () => {
  const sampleCsv = getSampleCsvTemplate();
  const report = parseAndValidateCsvQuestions(sampleCsv);

  assert.equal(report.headerErrors.length, 0);
  assert.equal(report.totalRows, 2);
  assert.equal(report.validCount, 2);
  assert.equal(report.invalidCount, 0);
  assert.equal(report.duplicateCount, 0);

  // Test duplicate detection and invalid row reporting
  const existingHashes = new Set([report.rows[0].contentHash]);
  const badRow = `"Histology & Cell Biology","","Too short","Opt A","Opt B","Opt C","","Z","","","" ,"","","Extreme","Tag","published"`;
  const mixedCsv = `${sampleCsv.trim()}\n${badRow}\n`;

  const secondReport = parseAndValidateCsvQuestions(mixedCsv, existingHashes);
  assert.equal(secondReport.totalRows, 3);
  assert.equal(secondReport.duplicateCount, 1); // first row matches existingHashes
  assert.equal(secondReport.validCount, 1); // second row is valid
  assert.equal(secondReport.invalidCount, 1); // third row has multiple validation errors
  assert.ok(secondReport.rows[2].errors.length >= 4);
});
