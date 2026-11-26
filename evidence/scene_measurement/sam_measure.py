import sys, json, numpy as np, cv2, torch
from segment_anything import sam_model_registry, SamPredictor
# usage: python3 sam_measure.py <sam_vit_b_01ec64.pth> <frame.png> <out_dir>
# frame.png: the 650 x 360 video area of the clip at t = 2 s. Point prompts below are in that frame's pixels.
CK, FRAME, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
img=cv2.imread(FRAME)
if img is None:
    sys.exit('ERROR: cannot read ' + FRAME)
rgb=cv2.cvtColor(img,cv2.COLOR_BGR2RGB)
sam=sam_model_registry['vit_b'](checkpoint=CK); pred=SamPredictor(sam); pred.set_image(rgb)
prompts={'pod':[(150,110),(180,90)],'suv':[(420,180),(560,170)],'suv_front_tyre':[(300,170)]}
out={}; vis=img.copy()
colors={'pod':(0,200,0),'suv':(255,0,0),'suv_front_tyre':(0,0,255)}
for k,pts in prompts.items():
    m,sc,_=pred.predict(point_coords=np.array(pts,float),point_labels=np.ones(len(pts)),multimask_output=True)
    i=int(np.argmax(sc)); mask=m[i]
    ys,xs=np.nonzero(mask)
    out[k]={'score':float(sc[i]),'x0':int(xs.min()),'x1':int(xs.max()),'y0':int(ys.min()),'y1':int(ys.max()),'area':int(mask.sum())}
    # bottom-row width (ground contact row band)
    yb=ys.max(); band=mask[max(0,yb-6):yb+1]; bx=np.nonzero(band.any(0))[0]
    out[k]['bottom_x0']=int(bx.min()); out[k]['bottom_x1']=int(bx.max())
    # leftmost point and its row
    li=np.argmin(xs); out[k]['left_pt']=[int(xs[li]),int(ys[li])]
    vis[mask]=(0.5*vis[mask]+0.5*np.array(colors[k])).astype(np.uint8)
# curb: edges + Hough, keep steep lines in the left third
g=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY); e=cv2.Canny(cv2.GaussianBlur(g,(5,5),0),40,120)
L=cv2.HoughLinesP(e,1,np.pi/180,60,minLineLength=80,maxLineGap=10)
cands=[]
if L is not None:
    for x1,y1,x2,y2 in np.asarray(L).reshape(-1,4):
        if max(x1,x2)<260 and abs(y2-y1)>abs(x2-x1)*0.8:
            cands.append((x1,y1,x2,y2)); cv2.line(vis,(x1,y1),(x2,y2),(0,255,255),2)
out['curb_lines']=[list(map(int,c)) for c in cands]
cv2.imwrite(OUT + '/frame_t2s_sam_overlay.png',cv2.resize(vis,None,fx=2,fy=2))
json.dump(out,open(OUT + '/f2_sam.json','w'),indent=1)
print(json.dumps(out,indent=1))
