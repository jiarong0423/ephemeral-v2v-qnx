/*
 * v2v_defence_iru.inc.c - G20: connection of the D1 defence state machine to the G17 independent reporting unit (IRU), and the
 * OpenSSL wrappers for leases, delegations and lease commands. Compiled only with -DV2V_DEFENCE. Include AFTER src/v2v_iru.inc.c
 * (crypto helpers, unit monitor, report layout) and src/v2v_defence.inc.c. Simulation only.
 *
 * Inputs only: the adapters read the unit's state / report through const pointers and write nothing but a v2v_def_in_t. The unit
 * has no function here that could set the state machine, send RESUME or clear a restriction; its verdicts can only raise the level
 * (host unhealthy -> hard trigger S8, MRM line edge -> hard trigger, flood flag -> S6). Releasing the vehicle after an IRU MRM request
 * is the vehicle's own recovery path (dwell, damping, local confirmation); the unit's latch itself stays set (G17 rule).
 */
#ifdef V2V_DEFENCE
#ifndef V2V_IRU_H
#error "include src/v2v_iru.inc.c before src/v2v_defence_iru.inc.c"
#endif
_Static_assert(DEF_IRU_UNKNOWN == IRU_HEALTH_UNKNOWN && DEF_IRU_OK == IRU_HEALTH_OK && DEF_IRU_SUSPECT == IRU_HEALTH_SUSPECT &&
               DEF_IRU_UNHEALTHY == IRU_HEALTH_UNHEALTHY, "IRU verdict values");
_Static_assert(IRU_DEF_NORMAL == 0U && IRU_DEF_SUSPECT == 1U && IRU_DEF_DEFENCE == 2U && IRU_DEF_RECOVERING == 3U, "heartbeat states");

/* simulation: the unit monitor's current verdict and MRM line, as the vehicle's MRM path / unit link would present them */
static void v2v_def_in_from_iru_mon(v2v_def_in_t *in, const iru_mon_t *m) {
    in->iru_health = m->health;
    in->iru_mrm_line = m->mrm_latched;
    if (m->flood) in->flood = 1;
}
/* a unit report received by the vehicle. Only a report whose signature the caller verified with the UNIT key (role certificate
 * 0x80) is used; anything else is ignored (the host key cannot speak for the unit, E17). */
static void v2v_def_in_from_iru_ur(v2v_def_in_t *in, const iru_unit_report_t *ur, int verified_unit_role) {
    if (!verified_unit_role || ur->magic != IRU_UR_MAGIC || ur->version != IRU_MSG_VERSION) return;
    if (ur->kind == IRU_KIND_HOST_STATUS) return;
    in->iru_health = ur->host_health <= IRU_HEALTH_UNHEALTHY ? ur->host_health : IRU_HEALTH_UNHEALTHY;
    if (ur->flags & IRU_UR_FLAG_MRM) in->iru_mrm_line = 1;
    if (ur->flags & IRU_UR_FLAG_FLOOD) in->flood = 1;
}

/* ---- leases, delegations, commands: ECDSA P-256 with the G17 helpers ---- */
static int v2v_lease_sign(EVP_PKEY *k, v2v_lease_t *l) { return iru_sign(k, l, offsetof(v2v_lease_t, sig), l->sig); }
static int v2v_deleg_sign(EVP_PKEY *cloud, v2v_deleg_t *d) { return iru_sign(cloud, d, offsetof(v2v_deleg_t, sig), d->sig); }
static int v2v_lcmd_sign(EVP_PKEY *k, v2v_lcmd_t *c) { return iru_sign(k, c, offsetof(v2v_lcmd_t, sig), c->sig); }
/* fills sig_ok / deleg_sig_ok of a lease context: a cloud lease is checked with the cloud key; an RSU lease with the RSU key named in
 * the delegation, and the delegation itself with the cloud key */
static void v2v_lease_verify(const v2v_lease_t *l, EVP_PKEY *cloud_pub, const v2v_deleg_t *d, v2v_lease_ctx_t *cx) {
    cx->sig_ok = 0;
    cx->deleg_sig_ok = 0;
    if (l->auth_type == DEF_AUTH_CLOUD) {
        cx->sig_ok = (uint8_t)iru_verify(cloud_pub, l, offsetof(v2v_lease_t, sig), l->sig);
    } else if (l->auth_type == DEF_AUTH_EDGE && d != NULL) {
        cx->deleg_sig_ok = (uint8_t)iru_verify(cloud_pub, d, offsetof(v2v_deleg_t, sig), d->sig);
        EVP_PKEY *rk = iru_key_from_pub(d->rsu_pub);
        cx->sig_ok = (uint8_t)iru_verify(rk, l, offsetof(v2v_lease_t, sig), l->sig);
        EVP_PKEY_free(rk);
    }
}
static uint8_t v2v_lcmd_verify(const v2v_lcmd_t *c, EVP_PKEY *authority_pub) {
    return (uint8_t)iru_verify(authority_pub, c, offsetof(v2v_lcmd_t, sig), c->sig);
}
#endif /* V2V_DEFENCE */
