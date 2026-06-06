/* ── data/divisions.js ─────────────────────────────────────────────────── */
/* All division content. Edit here — never hardcode in app.js.             */

const DIVISIONS = {
  'mens-physique': {
    label: "Men's Physique",
    icon: '🏄',
    desc: 'Athletic upper-body. V-taper, conditioning, symmetry. Board shorts division — legs not judged.',
    criteria: ['V-Taper', 'Shoulder Width', 'Waist Tightness', 'Conditioning', 'Symmetry', 'Arm Definition', 'Upper Chest', 'Presentation'],
    muscleGroups: ['Shoulders', 'Arms', 'Chest', 'Lats', 'Waist', 'Overall Conditioning'],
    prompt: `You are judging under NPC/IFBB Men's Physique standards. Key criteria: V-taper / X-frame, shoulder-to-waist ratio, upper body conditioning, symmetry, arm and chest definition, waist tightness. Legs are NOT judged. Score benchmarks: 7 = competitive amateur, 8.5 = national-level, 9+ = elite/pro.`
  },
  'classic-physique': {
    label: 'Classic Physique',
    icon: '🏛️',
    desc: "Golden-era proportions. Fullness, conditioning, symmetry. Height-to-weight caps apply.",
    criteria: ['Proportions', 'Muscle Fullness', 'Conditioning', 'Symmetry', 'Waist Definition', 'Leg Development', 'Stage Presence', 'Golden-Era Look'],
    muscleGroups: ['Shoulders', 'Chest', 'Back', 'Arms', 'Legs', 'Waist', 'Overall Proportions'],
    prompt: `You are judging under NPC/IFBB Classic Physique standards. Criteria: golden-era proportions (Zane, Reeves), muscle fullness and roundness, conditioning (not shredded to bone), symmetry and flow, small waist with full upper body, developed legs. Height-to-weight caps — note if over or under. Score benchmarks: 7 = competitive amateur, 8.5 = national, 9+ = elite/pro.`
  },
  'open-bodybuilding': {
    label: 'Open Bodybuilding',
    icon: '⚡',
    desc: 'Maximum mass with extreme conditioning. No size limits. Full body judged head to foot.',
    criteria: ['Overall Mass', 'Conditioning', 'Symmetry', 'Proportion', 'Muscle Density', 'Leg Development', 'Back Thickness', 'Stage Presence'],
    muscleGroups: ['Chest', 'Back', 'Shoulders', 'Arms', 'Legs', 'Glutes', 'Overall Mass', 'Conditioning'],
    prompt: `You are judging under NPC/IFBB Open Bodybuilding standards. Criteria: maximum mass with extreme conditioning, symmetry and proportion despite size, muscle density and detail, full body development — no weak parts allowed at this level, back thickness and width, leg development. Bigger is better when conditioning is maintained. Score benchmarks: 7 = competitive amateur, 8.5 = national, 9+ = elite/pro.`
  },
  'aesthetic': {
    label: 'General Aesthetic',
    icon: '🎯',
    desc: 'Everyday attractiveness. Lean, athletic, proportional. Not competition-specific.',
    criteria: ['Leanness', 'Proportions', 'V-Taper', 'Arm Development', 'Chest Fullness', 'Visible Abs', 'Overall Balance', 'Athletic Look'],
    muscleGroups: ['Shoulders', 'Arms', 'Chest', 'Abs', 'Back', 'Legs', 'Overall Leanness'],
    prompt: `You are evaluating on a general aesthetic scale — not competition prep but how impressive this physique looks to an objective observer. Criteria: leanness and body fat, proportional development, shoulder-to-waist ratio, arm and chest development, visible abs, athletic/healthy appearance, upper-lower body balance. Score benchmarks: 5 = average fit person, 7 = noticeably impressive, 8.5 = exceptional, 9+ = elite aesthetic.`
  }
};
