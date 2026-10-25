package com.ghostlock.app.ui

import com.ghostlock.app.domain.model.StrideCandidateOption
import com.ghostlock.app.domain.model.StrideProbe
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StrideRecommendationTest {
    private fun candidate(value: Int, votes: Int, samples: Int) =
        StrideCandidateOption(
            value = value,
            votes = votes,
            samples = samples,
            objectsPerSlab = 32768 / value,
        )

    private fun probe(
        samples: Int,
        vararg candidates: StrideCandidateOption,
        decided: Boolean = candidates.isNotEmpty() &&
            candidates.count { it.votes == samples } == 1,
        rounds: Int = samples,
    ) = StrideProbe(
        candidates = candidates.toList(),
        rounds = rounds,
        samples = samples,
        gcd = 960,
        decided = decided,
    )

    @Test
    fun `two agreeing measurements recommend the unanimous stride`() {
        val recommendation = recommendStride(
            probe(2, candidate(960, 2, 2), candidate(1152, 1, 2), candidate(1280, 1, 2)),
        )

        assertEquals(StrideEvidenceLevel.CONSISTENT, recommendation.level)
        assertEquals(960, recommendation.recommendedValue)
        assertEquals(StrideReason.Agree(2), recommendation.reason)
    }

    @Test
    fun `a partial leader is still offered, with mixed evidence`() {
        val recommendation = recommendStride(
            probe(3, candidate(960, 2, 3), candidate(1152, 1, 3), decided = false),
        )

        assertEquals(StrideEvidenceLevel.MIXED, recommendation.level)
        assertEquals(960, recommendation.recommendedValue)
        assertEquals(StrideReason.Partial(2, 3, 1), recommendation.reason)
    }

    @Test
    fun `a tie between candidates recommends skipping`() {
        val recommendation = recommendStride(
            probe(2, candidate(960, 2, 2), candidate(1152, 2, 2), decided = false),
        )

        assertEquals(StrideEvidenceLevel.MIXED, recommendation.level)
        assertNull(recommendation.recommendedValue)
        assertEquals(StrideReason.Tie, recommendation.reason)
    }

    @Test
    fun `one usable measurement is insufficient`() {
        val recommendation = recommendStride(probe(1, candidate(960, 1, 1)))

        assertEquals(StrideEvidenceLevel.INSUFFICIENT, recommendation.level)
        assertNull(recommendation.recommendedValue)
        assertEquals(StrideReason.Single(1), recommendation.reason)
    }

    @Test
    fun `no candidate at all is insufficient`() {
        val recommendation = recommendStride(probe(0))

        assertEquals(StrideEvidenceLevel.INSUFFICIENT, recommendation.level)
        assertNull(recommendation.recommendedValue)
        assertEquals(StrideReason.Single(0), recommendation.reason)
    }

    @Test
    fun `a root measurement wins even when the leak table agrees`() {
        val recommendation = recommendStride(
            probe(2, candidate(960, 2, 2)),
            confirmedValue = 960,
        )

        assertEquals(StrideEvidenceLevel.CONFIRMED, recommendation.level)
        assertEquals(960, recommendation.recommendedValue)
        assertEquals(960, recommendation.confirmedValue)
        assertEquals(StrideReason.ConfirmedAgree(2), recommendation.reason)
    }

    @Test
    fun `a root measurement wins even when the leak table does not list it`() {
        val recommendation = recommendStride(
            probe(2, candidate(960, 2, 2)),
            confirmedValue = 1024,
        )

        assertEquals(StrideEvidenceLevel.CONFIRMED, recommendation.level)
        assertEquals(1024, recommendation.recommendedValue)
        assertEquals(StrideReason.ConfirmedOnly(2), recommendation.reason)
    }
}
