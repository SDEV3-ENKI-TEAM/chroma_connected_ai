import os
import json
import re
import pandas as pd
import openai

from chroma_utils import (
    init_chroma,
    get_or_create_collection,
    embed_texts,
    insert_embeddings,
)

openai.api_key = os.getenv("OPENAI_API_KEY")
# if not openai.api_key:
#     raise RuntimeError("OPENAI_API_KEY 환경 변수를 설정하세요.")

NORM_RULES = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27,}", re.IGNORECASE), "<GUID>"),
    (re.compile(r"\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{32}\b"), "<HASH>"),
    (re.compile(r"\bpid:\d+\b", re.IGNORECASE), "<PID>"),
    (re.compile(r"C:\\Users\\[^\\]+", re.IGNORECASE), "%USERPROFILE%"),
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"), "<TIME>"),
]


def normalize_text(s):
    # 정규화 규칙 적용
    # 문자열 아니면 그대로 반환
    if not isinstance(s, str):  # s, str
        return s
    for pat, tok in NORM_RULES:
        s = pat.sub(tok, s)
    return s.lower()


# exe만 추출 // command line은 너무 길다...
def clean_cmd(cmd):
    if isinstance(cmd, str):
        m = re.search(r"([A-Za-z0-9_-]+\.exe)", cmd, re.IGNORECASE)
        return (
            m.group(1).lower() if m else cmd.lower()
        )  # 매칭값 있을 경우 / 아님 cmd 소문자화
    return cmd


def span_to_row(span):  # json -> dataframe 변환
    row = {
        "traceID": span.get("traceID"),
        "spanID": span.get("spanID"),
        "startTime": span.get("startTime"),
        "duration": span.get("duration", 0),
        # Sysmon / 분석 필드
        "SysmonEventID": None,
        "EventName": None,
        "PID": None,
        "ParentPID": None,
        "Executable": None,
        "CommandLine": None,
        "User": None,
        "SigmaAlert": None,
        "SigmaStatus": None,
    }  # span 객체 내부의 tags 리스트 순회
    for tag in span.get("tags", []):
        k, v = tag["key"], tag["value"]  # k, v 추출
        if k == "sysmon.event_id":
            row["SysmonEventID"] = v
        elif k == "EventName":
            row["EventName"] = v
        elif k == "sysmon.pid":
            row["PID"] = v
        elif k == "sysmon.ppid":
            row["ParentPID"] = v
        elif k == "Image":
            row["Executable"] = v
        elif k == "CommandLine":
            row["CommandLine"] = v
        elif k == "User":
            row["User"] = v
        elif k == "sigma.alert":
            row["SigmaAlert"] = v
        elif k == "otel.status_description":
            row["SigmaStatus"] = v
    return row


def main():
    # trace.json 파일 읽어오기 -> load 후 데이터 프레임
    with open(
        "E:\\AltF4\\agent\\preprocessing\\trace.json", "r", encoding="utf-8"
    ) as f:
        data = json.load(f).get("data", [])  # get : any

    # span -> row 변환
    rows = [span_to_row(span) for trace in data for span in trace.get("spans", [])]

    df = pd.DataFrame(rows)

    df["MainExecutable"] = (
        df["Executable"]
        .fillna("")
        .apply(lambda p: os.path.basename(p).lower())
        .apply(normalize_text)
    )
    df["MainCommand"] = (
        df["CommandLine"].fillna("").apply(clean_cmd).apply(normalize_text)
    )
    df["AttackType"] = (
        df["SigmaAlert"]
        .fillna("")
        .apply(lambda s: s.split("(", 1)[0])
        .apply(normalize_text)
    )
    df["IsSigmaDetected"] = df["SigmaAlert"].notna()

    for c in ["User", "EventName"]:
        df[c] = df[c].fillna("").apply(normalize_text)

    df = df.sort_values("startTime").reset_index(drop=True)
    out_path = "trace_cleaned.csv"
    df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"전처리 완료! 결과 파일: {out_path}")

    # 트레이스 단위로 청크 생성 // duration + 빈칸을 마커로 해서 세그먼트를 분리함
    trace_ids, chunks, metadatas = [], [], []
    for trace_id, group in df.groupby("traceID", sort=False):
        current = []
        for _, r in group.iterrows():
            if (  # duration만 있고 나머지 칼럼은 모두 빈 경우
                pd.isna(r.SysmonEventID)
                and pd.isna(r.EventName)
                and pd.isna(r.PID)
                and pd.isna(r.ParentPID)
                and not r.User
                and pd.isna(r.SigmaAlert)
                and not r.MainExecutable
                and not r.MainCommand
                and not r.IsSigmaDetected  # issigmadetected 값은 false여야함
                and not r.AttackType
            ):
                if current:
                    trace_ids.append(str(trace_id))
                    chunks.append(
                        "\n".join(
                            f"evt:{rr.SysmonEventID} img:{rr.MainExecutable} "
                            f"cmd:{rr.MainCommand} user:{rr.User} attack:{rr.AttackType}"
                            for rr in current
                        )
                    )
                    metadatas.append(
                        {
                            "traceID": str(trace_id),
                            "spanCount": len(current),
                            "hasAlert": any(rr.IsSigmaDetected for rr in current),
                        }
                    )
                    current = []
                continue
            current.append(r)
        # 마지막 세그먼트 처리 (남아있는건 다 저장)
        if current:
            trace_ids.append(str(trace_id))
            chunks.append(
                "\n".join(
                    f"evt:{rr.SysmonEventID} img:{rr.MainExecutable} "
                    f"cmd:{rr.MainCommand} user:{rr.User} attack:{rr.AttackType}"
                    for rr in current
                )
            )
            metadatas.append(
                {
                    "traceID": str(trace_id),
                    "spanCount": len(current),
                    "hasAlert": any(rr.IsSigmaDetected for rr in current),
                }
            )

    client = init_chroma(persist_directory="./chroma_db")
    collection = get_or_create_collection(client, "trace_embeddings")

    embeddings = embed_texts(chunks)
    insert_embeddings(
        collection=collection,
        ids=trace_ids,
        embeddings=embeddings,
        metadatas=metadatas,
        documents=chunks,
    )

    print(f"{len(trace_ids)} trace-vector를 Chroma에 저장했습니다.")

    # 테스트용 예제 검색
    query_emb = embeddings[:1]  # 첫 청크 벡터
    results = collection.query(
        query_embeddings=query_emb,
        n_results=3,
        include=["metadatas", "documents"],
    )
    print("\n— 예제 검색 결과 (첫 번째 trace 기준) —")
    for idx, meta, doc in zip(
        results["ids"][0], results["metadatas"][0], results["documents"][0]
    ):
        print(f"ID: {idx}")
        print(f"메타데이터: {meta}")
        print(f"청크 내용:\n{doc}\n")


if __name__ == "__main__":
    main()
