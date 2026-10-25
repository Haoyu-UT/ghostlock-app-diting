package com.ghostlock.app.ui

import com.ghostlock.app.domain.model.StrideCandidateOption
import com.ghostlock.app.domain.model.StrideProbe

/** How strong the stride evidence is, in plain language. */
enum class StrideEvidenceLevel { CONFIRMED, CONSISTENT, MIXED, INSUFFICIENT }

/**
 * Why the picker recommends what it recommends. The UI maps each case to a
 * localized one-liner; keeping the numbers in the type means the reason and the
 * table can never disagree.
 */
sealed interface StrideReason {
    /** A root measurement exists and the leak table agrees with it. */
    data class ConfirmedAgree(val samples: Int) : StrideReason

    /** A root measurement exists; the leak table does not corroborate it. */
    data class ConfirmedOnly(val samples: Int) : StrideReason

    /** Every usable leak measurement is divisible by the top candidate. */
    data class Agree(val samples: Int) : StrideReason

    /** The top candidate matches some, not all, measurements. */
    data class Partial(val matches: Int, val samples: Int, val runnerUp: Int) : StrideReason

    /** Two candidates tie; the evidence cannot choose between them. */
    data object Tie : StrideReason

    /** Fewer than two usable measurements (or none). */
    data class Single(val samples: Int) : StrideReason
}

data class StrideOptionValue(
    val value: Int,
    /** Usable measurements whose leaked offset is divisible by [value]. */
    val matches: Int,
    /** Usable measurements (nonzero offsets) — the denominator. */
    val samples: Int,
    /** ORDER3_SIZE / value, shown only in the technical details. */
    val objectsPerSlab: Int,
)

data class StrideRecommendation(
    val level: StrideEvidenceLevel,
    /** Value the primary action uses; null means "let the app scan" is safer. */
    val recommendedValue: Int?,
    /** Root-measured value, when a measured source is available. */
    val confirmedValue: Int?,
    val samples: Int,
    val rounds: Int,
    val gcd: Long,
    val options: List<StrideOptionValue>,
    val reason: StrideReason,
)

/**
 * What the stride sheet renders. The pending generated document stays in the
 * ViewModel; this is only the decision's presentation, so the sheet cannot act
 * on a document that was already consumed.
 */
data class StridePickerUiState(
    val recommendation: StrideRecommendation,
    /** Candidate currently selected; null means nothing is selected. */
    val selectedValue: Int?,
    /** Footer sentence stating what happens to the profile afterwards. */
    val footerRes: Int,
)

/**
 * Turns the probe's vote table into one recommendation plus an honest evidence
 * level. The rules:
 *
 * - a root-measured value wins outright (`CONFIRMED`), even when the leak table
 *   does not list it;
 * - otherwise ≥ 2 usable measurements with a unique unanimous top is
 *   `CONSISTENT`;
 * - a top candidate that matches only some measurements, or a tie at the top,
 *   is `MIXED`; a tie recommends skipping;
 * - fewer than 2 usable measurements is `INSUFFICIENT` and recommends skipping.
 */
internal fun recommendStride(
    probe: StrideProbe,
    confirmedValue: Int? = null,
): StrideRecommendation {
    val options = probe.candidates.map { candidate: StrideCandidateOption ->
        StrideOptionValue(
            value = candidate.value,
            matches = candidate.votes,
            samples = candidate.samples,
            objectsPerSlab = candidate.objectsPerSlab,
        )
    }
    val confirmed = confirmedValue?.takeIf { it > 0 }
    if (confirmed != null) {
        val agrees = probe.samples >= 2 && probe.candidates.any {
            it.value == confirmed && it.votes == probe.samples
        }
        return StrideRecommendation(
            level = StrideEvidenceLevel.CONFIRMED,
            recommendedValue = confirmed,
            confirmedValue = confirmed,
            samples = probe.samples,
            rounds = probe.rounds,
            gcd = probe.gcd,
            options = options,
            reason = if (agrees) {
                StrideReason.ConfirmedAgree(probe.samples)
            } else {
                StrideReason.ConfirmedOnly(probe.samples)
            },
        )
    }

    val top = probe.candidates.firstOrNull()
    val second = probe.candidates.getOrNull(1)
    if (top == null || probe.samples < 2) {
        return StrideRecommendation(
            level = StrideEvidenceLevel.INSUFFICIENT,
            recommendedValue = null,
            confirmedValue = null,
            samples = probe.samples,
            rounds = probe.rounds,
            gcd = probe.gcd,
            options = options,
            reason = StrideReason.Single(probe.samples),
        )
    }
    if (second != null && second.votes == top.votes) {
        return StrideRecommendation(
            level = StrideEvidenceLevel.MIXED,
            recommendedValue = null,
            confirmedValue = null,
            samples = probe.samples,
            rounds = probe.rounds,
            gcd = probe.gcd,
            options = options,
            reason = StrideReason.Tie,
        )
    }
    if (top.votes == probe.samples) {
        return StrideRecommendation(
            level = StrideEvidenceLevel.CONSISTENT,
            recommendedValue = top.value,
            confirmedValue = null,
            samples = probe.samples,
            rounds = probe.rounds,
            gcd = probe.gcd,
            options = options,
            reason = StrideReason.Agree(probe.samples),
        )
    }
    return StrideRecommendation(
        level = StrideEvidenceLevel.MIXED,
        recommendedValue = top.value,
        confirmedValue = null,
        samples = probe.samples,
        rounds = probe.rounds,
        gcd = probe.gcd,
        options = options,
        reason = StrideReason.Partial(top.votes, probe.samples, second?.votes ?: 0),
    )
}
