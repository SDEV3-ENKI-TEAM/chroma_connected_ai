# chroma_utils.py

import os
import openai
import chromadb
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE
from chromadb.utils import embedding_functions
from chromadb.errors import NotFoundError


def init_chroma(persist_directory: str = "./chroma_db"):
    """
    Initialize a local, SQLite‑backed Chroma PersistentClient.
    """
    os.makedirs(persist_directory, exist_ok=True)
    client = chromadb.PersistentClient(
        path=persist_directory,
        settings=Settings(),
        tenant=DEFAULT_TENANT,
        database=DEFAULT_DATABASE,
    )
    return client


def get_or_create_collection(client: chromadb.PersistentClient, name: str):
    try:
        return client.get_collection(name)
    except NotFoundError:
        return client.create_collection(
            name=name,
            embedding_function=embedding_functions.OpenAIEmbeddingFunction(
                api_key=os.getenv("OPENAI_API_KEY"), model_name="text-embedding-ada-002"
            ),
        )


def embed_texts(texts: list[str], model: str = "text-embedding-ada-002"):
    if not openai.api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")
    # note: lowercase "embeddings" in v1+
    resp = openai.embeddings.create(model=model, input=texts)
    return [choice.embedding for choice in resp.data]


def insert_embeddings(
    collection: chromadb.api.models.Collection.Collection,
    ids: list[str],
    embeddings: list[list[float]],
    metadatas: list[dict[str, str]],
    documents: list[str] | None = None,
):
    collection.add(
        ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents
    )
