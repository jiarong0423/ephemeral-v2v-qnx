#!/usr/bin/env python3
"""Takeover by arm x clearance x scene, and rule/map effects with seed-cluster bootstrap (B=20000) restricted to the pre-registered main clearance (clr 50 = need 260) and to each clearance. Exit 1 on bad input."""
import re, numpy as np, pandas as pd
P="<local-scratch>/qnx_reg_20261118/abl_full/spec2_b4m4abl_runs.csv"
d=pd.read_csv(P,usecols=["setting","arm","scene","trial","clr_cm","geo","takeover","stratum"])
assert len(d)==1782000
d["base"]=[re.sub(r"_(A00|A01|A11)_","_ARM_",s,count=1) for s in d.setting]
print("== takeover % by clearance x arm (all scenes)"); print((100*d.groupby(["clr_cm","arm"]).takeover.mean()).unstack().round(3).to_string())
print("== takeover % by scene x clearance x arm"); print((100*d.groupby(["scene","clr_cm","arm"]).takeover.mean()).unstack().round(3).to_string())
piv=d.pivot_table(index=["base","trial"],columns="arm",values="takeover",aggfunc="sum").reset_index()
meta=d.drop_duplicates("base").set_index("base")[["scene","clr_cm","geo"]]; piv=piv.merge(meta,left_on="base",right_index=True)
rng=np.random.default_rng(20261119); B=20000
def ci(sub,f):
    per=sub.assign(v=f(sub)).groupby("trial").v.mean().values*100; n=len(per); m=per[rng.integers(0,n,(B,n))].mean(1)
    return per.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
for lab,sub in [("clr50 all scenes",piv[piv.clr_cm==50]),("clr50 main geo",piv[(piv.clr_cm==50)&(piv.geo=="main")])]+[(f"clr50 {s}",piv[(piv.clr_cm==50)&(piv.scene==s)]) for s in ("M1","M2","M3")]:
    r=ci(sub,lambda x:x.A00-x.A01); g=ci(sub,lambda x:x.A01-x.A11)
    print(f"{lab:20s} pairs={sub.base.nunique():5d} rule {r[0]:6.2f} [{r[1]:6.2f},{r[2]:6.2f}]  map {g[0]:7.3f} [{g[1]:7.3f},{g[2]:7.3f}]  A00={100*sub.A00.mean():.2f}% A01={100*sub.A01.mean():.3f}% A11={100*sub.A11.mean():.3f}%")
