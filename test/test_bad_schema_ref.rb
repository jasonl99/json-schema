require 'test/unit'
require 'socket'
require File.dirname(__FILE__) + '/../lib/json-schema'

class BadSchemaRefTest < Test::Unit::TestCase

  def test_bad_uri_ref
    schema = {
        "$schema" => "http://json-schema.org/draft-04/schema#",
        "type" => "array",
        "items" => { "$ref" => "../google.json"}
    }

    data = [1,2,3]
    assert_raise(URI::BadURIError) do
      JSON::Validator.validate(schema,data)
    end
  end

  def test_bad_host_ref
    schema = {
        "$schema" => "http://json-schema.org/draft-04/schema#",
        "type" => "array",
        "items" => { "$ref" => "http://ppcheesecheseunicornnuuuurrrrr.com/json.schema"}
    }

    data = [1,2,3]
    assert_raise(SocketError) do
      JSON::Validator.validate(schema,data)
    end
  end

end