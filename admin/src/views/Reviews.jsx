import { useState, useEffect, useCallback, useRef } from 'react';
import { fetchReviews, reviewDoc, reviewDecision } from '../api.js';
import { Btn, Spinner, SectionLabel, Field, EmptyState, SkeletonRows, Card } from '../ui.jsx';
import { useToast } from '../contexts/ToastContext.jsx';
import { fmtDate } from '../lib.js';

// Pending-review queue + an inline review detail (image/liveness + the operator-confirmed fields). Polls
// every 10s while on the list (not mid-review).
export default function Reviews() {
  const { showToast } = useToast();
  const [reviews, setReviews] = useState(null);
  const [active, setActive] = useState(null); // the submission under review
  const [err, setErr] = useState('');

  const load = useCallback(async () => {
    try {
      const r = await fetchReviews();
      setReviews(r.items || []);
      setErr('');
    } catch (e) {
      setErr(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    if (active) return undefined;
    const id = setInterval(() => !document.hidden && load(), 10000);
    return () => clearInterval(id);
  }, [active, load]);

  if (active)
    return (
      <ReviewDetail
        review={active}
        onDone={(msg) => {
          if (msg) showToast(msg);
          setActive(null);
          load();
        }}
        onBack={() => setActive(null)}
      />
    );

  if (err) return <p className="text-[13px] text-danger">{err}</p>;
  if (reviews === null) return <SkeletonRows rows={4} />;

  return (
    <section>
      <SectionLabel count={reviews.length} className="mb-1">
        Pending reviews
      </SectionLabel>
      {reviews.length === 0 ? (
        <EmptyState title="No submissions waiting.">
          New verification submissions appear here for an operator to approve or reject.
        </EmptyState>
      ) : (
        <div className="border-t border-line divide-y divide-line">
          {reviews.map((r) => (
            <div key={r.sid} className="flex items-center gap-3 py-3.5">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">
                  {r.type} <span className="text-faint">· {r.method}</span>
                  {r.liveness && <span className="ml-2 text-[11px] text-accent">liveness</span>}
                </div>
                <div className="text-[12px] text-faint font-mono">{fmtDate(r.submittedAt)}</div>
              </div>
              <Btn variant="outline" onClick={() => setActive(r)}>
                Review
              </Btn>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// Fallback for a session whose type predates reviewFields (only `age` ever shipped without it).
const DEFAULT_FIELDS = [{ key: 'dob', label: 'Date of birth (from ID)', type: 'date', required: true }];

function ReviewDetail({ review, onDone, onBack }) {
  const { sid, type } = review;
  const fields = review.reviewFields?.length ? review.reviewFields : DEFAULT_FIELDS;
  const liveness = review.liveness; // { gestures: [{id,label}] } when a liveness clip was required
  const [img, setImg] = useState('');
  const [video, setVideo] = useState('');
  const [data, setData] = useState({});
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const headingRef = useRef(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  useEffect(() => {
    let url;
    reviewDoc(sid)
      .then((u) => {
        url = u;
        setImg(u);
      })
      .catch(() => setErr('Could not load the document.'));
    return () => url && URL.revokeObjectURL(url);
  }, [sid]);

  useEffect(() => {
    if (!liveness) return undefined;
    let url;
    reviewDoc(sid, 'liveness')
      .then((u) => {
        url = u;
        setVideo(u);
      })
      .catch(() => {});
    return () => url && URL.revokeObjectURL(url);
  }, [sid, liveness]);

  const setField = (k, v) => setData((d) => ({ ...d, [k]: v }));
  const missing = (f) => f.required && !String(data[f.key] || '').trim();
  const ready = fields.every((f) => !missing(f));

  const decide = async (approve) => {
    setErr('');
    setBusy(true);
    try {
      await reviewDecision(sid, approve, approve ? data : undefined);
      onDone(approve ? `Approved & issued — ${type}.` : 'Submission rejected.');
    } catch (e) {
      setErr(['bad_claims', 'bad_dob'].includes(e.message) ? 'Check the details entered from the ID.' : 'Decision failed — try again.');
      setBusy(false);
    }
  };

  return (
    <div>
      <button onClick={onBack} className="text-[13px] text-muted hover:text-ink transition-colors">
        ← Back to reviews
      </button>
      <h1 ref={headingRef} tabIndex={-1} className="text-[1.4rem] font-semibold tracking-tight mt-3 outline-none">
        Review submission <span className="text-faint text-[1rem]">· {type}</span>
      </h1>
      <p className="text-[13px] text-faint mt-1">
        Confirm the details below from the ID, then approve. The image is deleted on your decision.
      </p>

      <Card className="mt-5 overflow-hidden">
        {img ? (
          <img src={img} alt="Submitted ID" className="w-full max-h-[60vh] object-contain" />
        ) : (
          <div className="py-20 flex justify-center text-muted">
            {err ? <span className="text-danger text-sm">{err}</span> : <Spinner size={22} />}
          </div>
        )}
      </Card>

      {liveness && (
        <div className="mt-5">
          <SectionLabel className="mb-2">Liveness check</SectionLabel>
          <div className="rounded-2xl border border-line overflow-hidden bg-black">
            {video ? (
              <video src={video} controls playsInline className="w-full max-h-[60vh]" />
            ) : (
              <div className="py-16 flex justify-center text-muted">
                <Spinner size={22} />
              </div>
            )}
          </div>
          <p className="text-[12px] text-muted mt-2">
            Confirm a <strong className="text-ink font-medium">live person matching the ID</strong> performed, in
            order: {(liveness.gestures || []).map((g) => g.label).join(' → ') || '—'}.
          </p>
        </div>
      )}

      <div className="mt-5 max-w-sm space-y-4">
        {fields.map((f) =>
          f.type === 'select' ? (
            <label key={f.key} className="block">
              <span className="block text-[11px] uppercase tracking-[0.14em] text-faint mb-1.5">{f.label}</span>
              <select
                value={data[f.key] || ''}
                aria-invalid={missing(f)}
                onChange={(e) => setField(f.key, e.target.value)}
                className={`w-full bg-transparent border-0 border-b rounded-none px-0 py-2.5 text-ink outline-none transition-colors focus:border-accent ${missing(f) ? 'border-danger/50' : 'border-line'}`}
              >
                <option value="">Select…</option>
                {(f.options || []).map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <Field
              key={f.key}
              label={f.label}
              type={f.type === 'date' ? 'date' : 'text'}
              value={data[f.key] || ''}
              aria-invalid={missing(f)}
              onChange={(e) => setField(f.key, e.target.value)}
            />
          ),
        )}
      </div>

      {err && img && <p className="text-[13px] text-danger mt-3">{err}</p>}
      <div className="flex items-center gap-2 mt-6">
        <Btn onClick={() => decide(true)} disabled={busy || !ready}>
          {busy ? (
            <>
              <Spinner /> Working…
            </>
          ) : (
            'Approve & issue'
          )}
        </Btn>
        <Btn variant="danger" onClick={() => decide(false)} disabled={busy}>
          Reject
        </Btn>
      </div>
    </div>
  );
}
