import os, cv2, numpy as np
from ai_edge_litert.interpreter import Interpreter
LABELS = [l.strip() for l in open(os.path.join(os.path.dirname(__file__), "labels.txt"), encoding="utf8") if l.strip()]

class Detector:
    """YOLOv8 TFLite (input 1x3x640x640 float32, output 1x23x8400 = 4 box + 19 classes)."""
    def __init__(s, path, conf=None, iou=.45):
        s.i = Interpreter(model_path=path, num_threads=4); s.i.allocate_tensors()
        s.inp = s.i.get_input_details()[0]; s.out = s.i.get_output_details()[0]
        sh = s.inp["shape"]; s.nchw = sh[1] == 3; s.size = int(sh[2] if s.nchw else sh[1])
        s.conf, s.iou = conf if conf is not None else float(os.environ.get('DAP_CONF', .80)), iou
        s.train = int(os.environ.get('DAP_TRAIN_SIZE', 640))  # taille d'entraînement : l'image est réduite à cette taille puis placée sur le canevas du modèle

    def __call__(s, img):
        h, w = img.shape[:2]; r = min(s.size, s.train) / max(h, w); nh, nw = int(h * r), int(w * r)
        py, px = (s.size - nh) // 2, (s.size - nw) // 2
        can = np.full((s.size, s.size, 3), 114, np.uint8); can[py:py+nh, px:px+nw] = cv2.resize(img, (nw, nh))
        x = cv2.cvtColor(can, cv2.COLOR_BGR2RGB).astype(np.float32) / 255
        x = x.transpose(2, 0, 1)[None] if s.nchw else x[None]
        s.i.set_tensor(s.inp["index"], np.ascontiguousarray(x)); s.i.invoke()
        o = s.i.get_tensor(s.out["index"])[0]
        if o.shape[0] < o.shape[1]: o = o.T
        b, sc = o[:, :4].copy(), o[:, 4:]
        cid, cf = sc.argmax(1), sc.max(1); m = cf >= s.conf
        b, cid, cf = b[m], cid[m], cf[m]
        if not len(b): return []
        if b.max() <= 1.5: b *= s.size
        xy = np.stack([b[:, 0]-b[:, 2]/2, b[:, 1]-b[:, 3]/2, b[:, 2], b[:, 3]], 1)
        keep = cv2.dnn.NMSBoxes(xy.tolist(), cf.tolist(), s.conf, s.iou)
        res = []
        for j in np.array(keep).flatten():
            x0, y0, bw, bh = xy[j]
            bx = [float(np.clip((x0-px)/r, 0, w)), float(np.clip((y0-py)/r, 0, h)),
                  float(np.clip((x0+bw-px)/r, 0, w)), float(np.clip((y0+bh-py)/r, 0, h))]
            res.append({"parasite": LABELS[int(cid[j])], "class_id": int(cid[j]), "conf": round(float(cf[j]), 3), "box": bx})
        return res

def draw(img, dets):
    out = img.copy(); t = max(2, img.shape[1] // 400)
    for d in dets:
        x0, y0, x1, y1 = map(int, d["box"]); k = d["class_id"]
        col = ((k*47) % 200 + 40, (k*91) % 200 + 40, (k*131) % 200 + 40)
        cv2.rectangle(out, (x0, y0), (x1, y1), col, t)
        cv2.putText(out, f'{d["parasite"]} {d["conf"]:.2f}', (x0, max(15, y0-5)), cv2.FONT_HERSHEY_SIMPLEX, max(.5, t/4), col, t)
    return out
