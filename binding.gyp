{
    "targets": [
        {
            "target_name": "grin-hashing",
            "sources": [
                "cuckaroo29.cc",
                "cuckatoo31.cc",
                "src/blake2b-ref.c"
            ],
            "include_dirs": [
                "src",
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
