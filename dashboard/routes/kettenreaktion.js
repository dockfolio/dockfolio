/**
 * Kettenreaktion API — daily puzzle backend.
 * 3 routes: submit result, get stats, get heatmap.
 */
export default function registerKettenreaktionRoutes({ app, db, rateLimit }) {
  // Create table if not exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS kr_daily_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      player_id TEXT NOT NULL,
      puzzle_date TEXT NOT NULL,
      score INTEGER NOT NULL,
      solved INTEGER NOT NULL DEFAULT 0,
      attempts INTEGER NOT NULL DEFAULT 1,
      chain_length INTEGER NOT NULL DEFAULT 0,
      placement_type TEXT,
      placement_x REAL,
      placement_y REAL,
      solve_time_ms INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(player_id, puzzle_date)
    )
  `);

  // Index for fast daily queries
  db.exec(`CREATE INDEX IF NOT EXISTS idx_kr_puzzle_date ON kr_daily_results(puzzle_date)`);

  // Prepared statements
  const insertResult = db.prepare(`
    INSERT OR IGNORE INTO kr_daily_results
      (player_id, puzzle_date, score, solved, attempts, chain_length, placement_type, placement_x, placement_y, solve_time_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const getStats = db.prepare(`
    SELECT
      COUNT(*) as total_players,
      SUM(CASE WHEN solved = 1 THEN 1 ELSE 0 END) as total_solved,
      ROUND(AVG(score), 0) as avg_score,
      MAX(score) as best_score,
      MIN(score) as worst_score
    FROM kr_daily_results
    WHERE puzzle_date = ?
  `);

  const getScoreHistogram = db.prepare(`
    SELECT
      CASE
        WHEN score < 200 THEN '0-199'
        WHEN score < 400 THEN '200-399'
        WHEN score < 600 THEN '400-599'
        WHEN score < 800 THEN '600-799'
        WHEN score < 1000 THEN '800-999'
        ELSE '1000+'
      END as bucket,
      COUNT(*) as count
    FROM kr_daily_results
    WHERE puzzle_date = ?
    GROUP BY bucket
    ORDER BY MIN(score)
  `);

  const getPlacements = db.prepare(`
    SELECT placement_x, placement_y, placement_type
    FROM kr_daily_results
    WHERE puzzle_date = ? AND placement_x IS NOT NULL
  `);

  const getPlayerResult = db.prepare(`
    SELECT score FROM kr_daily_results WHERE player_id = ? AND puzzle_date = ?
  `);

  const getPlayerRank = db.prepare(`
    SELECT COUNT(*) as rank FROM kr_daily_results
    WHERE puzzle_date = ? AND score > ?
  `);

  // Rate limiters
  const rlSubmit = rateLimit(30, 60000);   // 30 submissions/min
  const rlRead = rateLimit(120, 60000);    // 120 reads/min

  // CORS for cross-origin requests from the game
  const setCORS = (res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
  };

  // OPTIONS preflight
  app.options('/api/kr/result', (req, res) => { setCORS(res); res.sendStatus(204); });
  app.options('/api/kr/stats', (req, res) => { setCORS(res); res.sendStatus(204); });
  app.options('/api/kr/heatmap', (req, res) => { setCORS(res); res.sendStatus(204); });

  // POST /api/kr/result — submit daily result
  app.post('/api/kr/result', rlSubmit, (req, res) => {
    setCORS(res);
    try {
      const { playerId, puzzleDate, score, solved, attempts, chainLength, placement, solveTimeMs } = req.body;

      if (!playerId || !puzzleDate || score === undefined) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      // Validate score range
      if (typeof score !== 'number' || score < 0 || score > 5000) {
        return res.status(400).json({ error: 'Invalid score' });
      }

      // Validate date format (YYYY-MM-DD)
      if (!/^\d{4}-\d{2}-\d{2}$/.test(puzzleDate)) {
        return res.status(400).json({ error: 'Invalid date format' });
      }

      const result = insertResult.run(
        playerId,
        puzzleDate,
        Math.round(score),
        solved ? 1 : 0,
        attempts ?? 1,
        chainLength ?? 0,
        placement?.type ?? null,
        placement?.x != null ? Math.round(placement.x) : null,
        placement?.y != null ? Math.round(placement.y) : null,
        solveTimeMs ?? null
      );

      if (result.changes === 0) {
        return res.json({ ok: true, duplicate: true });
      }

      res.json({ ok: true });
    } catch (err) {
      console.error('[KR] Submit error:', err.message);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // GET /api/kr/stats?date=YYYY-MM-DD — get daily stats
  app.get('/api/kr/stats', rlRead, (req, res) => {
    setCORS(res);
    try {
      const date = req.query.date || new Date().toISOString().split('T')[0];

      const stats = getStats.get(date);
      const histogram = getScoreHistogram.all(date);

      // Compute percentile for a specific player
      let percentile = null;
      const playerId = req.query.playerId;
      if (playerId) {
        const playerResult = getPlayerResult.get(playerId, date);
        if (playerResult && stats.total_players > 0) {
          const rank = getPlayerRank.get(date, playerResult.score);
          percentile = Math.round(((stats.total_players - rank.rank) / stats.total_players) * 100);
        }
      }

      res.json({
        date,
        totalPlayers: stats.total_players,
        solveRate: stats.total_players > 0 ? Math.round((stats.total_solved / stats.total_players) * 100) : 0,
        avgScore: stats.avg_score ?? 0,
        bestScore: stats.best_score ?? 0,
        histogram,
        percentile,
      });
    } catch (err) {
      console.error('[KR] Stats error:', err.message);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // GET /api/kr/heatmap?date=YYYY-MM-DD — placement heatmap data
  app.get('/api/kr/heatmap', rlRead, (req, res) => {
    setCORS(res);
    try {
      const date = req.query.date || new Date().toISOString().split('T')[0];
      const placements = getPlacements.all(date);

      // Bin placements into a 16x12 grid (800/50 x 600/50)
      const GRID_W = 16;
      const GRID_H = 12;
      const CELL_W = 800 / GRID_W;
      const CELL_H = 600 / GRID_H;
      const grid = Array.from({ length: GRID_W * GRID_H }, () => 0);

      for (const p of placements) {
        const gx = Math.min(GRID_W - 1, Math.max(0, Math.floor(p.placement_x / CELL_W)));
        const gy = Math.min(GRID_H - 1, Math.max(0, Math.floor(p.placement_y / CELL_H)));
        grid[gy * GRID_W + gx]++;
      }

      // Top 5 placement spots
      const topSpots = placements.reduce((acc, p) => {
        const key = `${Math.round(p.placement_x / 10) * 10},${Math.round(p.placement_y / 10) * 10}`;
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});

      const top5 = Object.entries(topSpots)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([coords, count]) => {
          const [x, y] = coords.split(',').map(Number);
          return { x, y, count, pct: Math.round((count / placements.length) * 100) };
        });

      res.json({
        date,
        totalPlacements: placements.length,
        grid: { width: GRID_W, height: GRID_H, cells: grid },
        topSpots: top5,
      });
    } catch (err) {
      console.error('[KR] Heatmap error:', err.message);
      res.status(500).json({ error: 'Server error' });
    }
  });

  console.log('[KR] Kettenreaktion routes registered');
}
