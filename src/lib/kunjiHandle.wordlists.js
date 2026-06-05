/**
 * Canonical wordlists for the deterministic default identity (see kunjiHandle.js).
 * NAMES: gender-agnostic surnames (curated, multi-origin). ADJECTIVES: strictly
 * positive/neutral so every adjective+name pairing reads kindly.
 *
 * ⚠️ These lists are a cross-RP rendering CONTRACT. The mapping uses each list's
 * length (modulo), so reordering, adding, or removing words changes which name an
 * existing `sub` resolves to — i.e. it re-skins every user's default display name.
 * That is cosmetic (never a lockout — `sub` stays the account key), but any change
 * should be treated as a versioned break and mirrored in docs/discoverable-login.md.
 */

export const ADJECTIVES = [
  'Amber', 'Cobalt', 'Slate', 'Cedar', 'Ember', 'Ivory', 'Indigo', 'Sage', 'Umber', 'Ochre',
  'Copper', 'Onyx', 'Pearl', 'Russet', 'Sienna', 'Teal', 'Azure', 'Hazel', 'Flint', 'Marble',
  'Calm', 'Bright', 'Brave', 'Bold', 'Keen', 'Kind', 'Swift', 'True', 'Lucid', 'Quiet',
  'Gentle', 'Steady', 'Clever', 'Wise', 'Witty', 'Merry', 'Glad', 'Deft', 'Agile', 'Nimble',
  'Spry', 'Sunny', 'Jovial', 'Serene', 'Placid', 'Candid', 'Earnest', 'Ardent', 'Eager', 'Lively',
  'Vivid', 'Radiant', 'Mellow', 'Tranquil', 'Patient', 'Humble', 'Noble', 'Loyal', 'Frank', 'Astute',
  'Adept', 'Fluent', 'Graceful', 'Poised', 'Polished', 'Refined', 'Dapper', 'Suave', 'Jaunty', 'Breezy',
  'Warm', 'Fond', 'Fair', 'Just', 'Sterling', 'Stellar', 'Lunar', 'Solar', 'Dawn', 'Dusk',
  'Autumn', 'Winter', 'Summer', 'Frost', 'Mist', 'Storm', 'Willow', 'Aspen', 'Maple', 'Alder',
  'Birch', 'Juniper', 'River', 'Meadow', 'Harbor', 'Summit', 'North', 'Ridge', 'Vale', 'Haven',
  'Cinder', 'Saffron', 'Marigold', 'Cordial', 'Jolly', 'Spirited', 'Buoyant', 'Chipper', 'Affable', 'Genial',
  'Cosmic', 'Verdant', 'Pristine', 'Crisp', 'Brisk', 'Plucky', 'Dashing', 'Gallant', 'Valiant', 'Resolute',
];

export const NAMES = [
  'Addison', 'Avery', 'Bailey', 'Barrett', 'Bellamy', 'Bennett', 'Blair', 'Blake', 'Brooks', 'Carter',
  'Chase', 'Cole', 'Cooper', 'Courtney', 'Darby', 'Drake', 'Elliot', 'Ellis', 'Emerson', 'Fletcher',
  'Foster', 'Fox', 'Gray', 'Hadley', 'Harper', 'Hayden', 'Hudson', 'Hunter', 'Jordan', 'Kendall',
  'Logan', 'Mason', 'Mercer', 'Morgan', 'Parker', 'Payton', 'Quinn', 'Riley', 'Spencer', 'Cameron',
  'Campbell', 'Finley', 'Fraser', 'Kennedy', 'Mackenzie', 'Marlowe', 'Rowan', 'Dupont', 'Laurent', 'Marceau',
  'Renard', 'Cruz', 'Delgado', 'Fuentes', 'Leal', 'Montoya', 'Reyes', 'Serrano', 'Vargas', 'Vega',
  'Amara', 'Asante', 'Diallo', 'Jomo', 'Kamau', 'Kofi', 'Mensah', 'Osei', 'Zuri', 'Arora',
  'Chandra', 'Jahan', 'Kapoor', 'Nair', 'Patel', 'Rajan', 'Singh', 'Hayashi', 'Inoue', 'Kimura',
  'Ren', 'Sato', 'Yuki', 'Bae', 'Jeon', 'Kim', 'Lim', 'Yoon', 'Chen', 'Lin',
  'Wei', 'Xin', 'Amin', 'Jaber', 'Nasser', 'Saleh', 'Andersen', 'Berg', 'Dahl', 'Lund',
  'Fujimoto', 'Hamada', 'Ishida', 'Kato', 'Matsuda', 'Mori', 'Nakamura', 'Ono', 'Suzuki', 'Tanaka',
  'Watanabe', 'Yamamoto', 'Ahn', 'Cho', 'Choi', 'Han', 'Kang', 'Ko', 'Lee', 'Min',
  'Moon', 'Oh', 'Park', 'Shin', 'Song', 'Fang', 'Guo', 'He', 'Huang', 'Liu',
  'Lu', 'Ma', 'Tang', 'Wang', 'Wu', 'Yang', 'Zhang', 'Zhao', 'Zhou', 'Dang',
  'Dinh', 'Do', 'Ho', 'Le', 'Ngo', 'Nguyen', 'Pham', 'Tran', 'Vu', 'Bautista',
  'Dela Cruz', 'Santos', 'Villanueva', 'Gunawan', 'Hidayat', 'Kusuma', 'Santoso', 'Wijaya', 'Charoenwong', 'Jaidee',
  'Noi', 'Prasert', 'Somboon', 'Agarwal', 'Chauhan', 'Gupta', 'Joshi', 'Mishra', 'Sharma', 'Shukla',
  'Sinha', 'Tiwari', 'Yadav', 'Banerjee', 'Bose', 'Chakraborty', 'Chatterjee', 'Das', 'Ghosh', 'Mukherjee',
  'Roy', 'Sen', 'Iyer', 'Iyengar', 'Kumar', 'Murugan', 'Pillai', 'Subramanian', 'Naidu', 'Reddy',
  'Rao', 'Varma', 'Gowda', 'Hegde', 'Shetty', 'Menon', 'Nambiar', 'Anand', 'Bains', 'Dhaliwal',
  'Gill', 'Grewal', 'Sandhu', 'Desai', 'Mehta', 'Shah', 'Deshpande', 'Kulkarni', 'Patil', 'Bhat',
  'Dar', 'Wani',
];
