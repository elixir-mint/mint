# Used by "mix format"
[
  inputs: ["mix.exs", "{lib,test}/**/*.{ex,exs}"],
  locals_without_parens: [
    # TODO: remove this once we depend on newer stream_data, which provide this if you
    # import their configuration.
    all: :*,
    assert_round_trip: 1,
    assert_recv_frames: 1,
    assert_http2_error: 2
  ]
]
