require 'uri'
require 'open-uri'
require 'pathname'
require 'bigdecimal'
require 'digest/sha1'
require 'date'
require 'thread'
require 'yaml'
require 'active_support/core_ext/hash/indifferent_access'

module JSON

  class Schema
    class ValidationError < StandardError
      attr_accessor :fragments, :schema, :failed_attribute, :sub_errors

      def initialize(message, fragments, failed_attribute, schema, options = {})
        @fragments = fragments.clone
        @schema = schema
        @sub_errors = []
        @failed_attribute = failed_attribute
        @options = options
        super(message)
      end

      def attribute_name(fragments)
        "[#{fragments.join(' / ')}]"
      end

      def to_string
        case
        when @sub_errors.empty?
          message
        when @sub_errors.count==1
          @sub_errors.first.to_string
        else 
         template = schema.schema.fetch(:error_message,false) || JSON::Validator.description(failed_attribute.to_s(:lower))
         template % schema.schema.merge(attribute: attribute_name(fragments), validation_array: @sub_errors.map(&:to_string).join(', '), ).deep_symbolize_keys
        end
      end

      def to_hash
        base = {:schema => @schema.uri, :fragment => ::JSON::Schema::Attribute.build_fragment(fragments), :message => message, :failed_attribute => @failed_attribute.to_s(:lower)}
        base.merge! data_attributes
        case
        when @sub_errors.count == 1
          base[:message] = sub_errors.first.message
        when !@sub_errors.empty?
          base[:message] = sub_errors.map(&:message).each_with_index.inject('') do |col, (m,idx)| 
            col += case
            when sub_errors.count==1 || idx==0 then ''
            when idx=sub_errors.count - 1 && sub_errors.count >= 2 then ' and '
            else ' -,- '
            end + "[#{m}]"
          end
        end
        base[:errors] = @sub_errors.map{|e| e.to_hash}
        base.delete(:schema) unless @options[:include_schema_in_objects]
        base
      end

      # extracts any keys that start with 'data-' or 'data_' and returns those keys with the 'data' preface stripped
      def data_attributes
        @schema.schema.select {|k,_| k.to_s.start_with?('data_') or k.to_s.start_with?('data-')}.inject({}) {|col,(k,v)| col[k[5..-1].to_sym]=v;col}
      end

    end

    class SchemaError < StandardError
    end

    class JsonParseError < StandardError
    end

    class Attribute

      attr_accessor :message

      def self.to_s(modifier = nil)
        s = super().split(":").last.split("Attribute").first
        modifier==:lower ? uncapitalize(s) : s
      end

      def self.validate(current_schema, data, fragments, processor, validator, options = {})
      end

      def self.build_fragment(fragments)
        "#/#{fragments.join('/')}"
      end

      def self.attribute_name(fragments)
        "[#{fragments.join(' / ')}]"
      end

      def self.uncapitalize(string)
        string[0,1].downcase + string[1..-1]
      end

      def self.error_message(args)
        # note the assignment (error_template = ...) is INTENTIONAL (this does NOT test for equality ==).
        # if a templat exists, assign it and use it, other wise just put out the problem message.
        if error_template = args[:schema].fetch(:error_message,JSON::Validator.description(args[:failed_attribute]))
          message = error_template % args[:schema].deep_symbolize_keys.merge(
              attribute: attribute_name(args[:fragments]), 
              data: args[:data], 
              validation_array: Array(args[:schema][args[:failed_attribute]]).join(', '))
        else
          message = args[:message]
        end
      end

      def self.validation_error(processor, message, fragments, current_schema, failed_attribute, record_errors)
        message = error_message(
          data: processor.data(fragments), 
          schema: current_schema.schema, 
          failed_attribute: uncapitalize(failed_attribute.to_s),
          message: message,
          fragments: fragments
          )
        error = ValidationError.new(message, fragments, failed_attribute, current_schema, processor.options)
        if record_errors
          processor.validation_error(error)
        else
          raise error
        end
      end

      def self.validation_errors(validator)
        validator.validation_errors
      end
    end

    class Validator
      attr_accessor :attributes, :uri

      def initialize()
        @attributes = {}
        @uri = nil
      end

      def extend_schema_definition(schema_uri)
        u = URI.parse(schema_uri)
        validator = JSON::Validator.validators["#{u.scheme}://#{u.host}#{u.path}"]
        if validator.nil?
          raise SchemaError.new("Schema not found: #{u.scheme}://#{u.host}#{u.path}")
        end
        @attributes.merge!(validator.attributes)
      end

      def to_s
        "#{@uri.scheme}://#{uri.host}#{uri.path}"
      end

      def validate(current_schema, data, fragments, processor, options = {})
        current_schema.schema.each do |attr_name,attribute|
          if @attributes.has_key?(attr_name.to_s)
            @attributes[attr_name.to_s].validate(current_schema, data, fragments, processor, self, options)
          end
        end
        data
      end
    end
  end


  class Validator

    attr_accessor :errors, :options

    @@schemas = {}
    @@cache_schemas = false
    @@default_opts = {
      :list => false,
      :version => nil,
      :validate_schema => false,
      :record_errors => false,
      :errors_as_objects => false,
      :insert_defaults => false,
      :clear_cache => true,
      :strict => false,
      include_schema_in_objects: false
    }
    @@validators = {}
    @@default_validator = nil
    @@available_json_backends = []
    @@json_backend = nil
    @@serializer = nil
    @@mutex = Mutex.new

    def data(fragments = [])
      # pull the data out based on the path passed (fragments)
      fragments.inject(ActiveSupport::HashWithIndifferentAccess.new(@data),:fetch)
    end

    def self.description(key)
      @descriptions ||= ActiveSupport::HashWithIndifferentAccess.new(
        {
          typeV4: '%{attribute} must a %{type}',
          type: '%{attribute} must a %{type}',
          allOf: '%{attribute} must meet all of the follow criteria: [%{validation_array}]',
          anyOf: '%{attribute} must meet at least one of the following criteria: [%{validation_array}]',
          oneOf: '%{attribute} must meet exactly one of the following criteria: [%{validation_array}]',
          "not" => 'Must not meet this critera',
          disallow: 'Description for disallow', 
          format: '%{attribute} must be in this format',
          maximum: '%{attribute} must be at most %{maximum}',
          minimum: '%{attribute} must be at least %{minimum}',
          minItems: '%{attribute} must have at most %{minItems} items',
          maxItems: '%{attribute} must have at least %{maxItems} items',
          minProperties: '%{attribute} must have at least %{minProperties} properties',
          maxProperties: '%{attribute} must have at least %{maxProperties} properties',
          uniqueItems: '%{attribute} must have unique items',
          minLength: '%{attribute} must be at least %{minLength} characters', 
          maxLength: '%{attribute} must be at most %{maxLength} characters',
          multipleOf: '%{attribute} must be a multiple of %{multipleOf}',
          enum: '%{attribute} must be one of the following values: [%{validation_array}]',
          properties: '%{attribute} must have the following properties: %{properties}',
          required: 'The following properties are required: [%{validation_array}]', 
          pattern: 'The value must meet the pattern %{pattern}',
          patternProperties: 'The property key must meet the pattern %{pattern}',
          additionalProperties: 'Additional properties beyond those specified are not allowed',
          items: 'Items are required',
          additionalItems: 'Additional items are not allowed',
          dependencies: 'Dependencies Description',
          extends: 'Extends description'
        })
      @descriptions.fetch(key,nil)
    end

    def self.version_string_for(version)
      # I'm not a fan of this, but it's quick and dirty to get it working for now
      return "draft-04" unless version
      case version.to_s
      when "draft4", "http://json-schema.org/draft-04/schema#"
        "draft-04"
      when "draft3", "http://json-schema.org/draft-03/schema#"
        "draft-03"
      when "draft2"
        "draft-02"
      when "draft1"
        "draft-01"
      else
        raise JSON::Schema::SchemaError.new("The requested JSON schema version is not supported")
      end
    end

    def self.metaschema_for(version_string)
      File.join(Pathname.new(File.dirname(__FILE__)).parent.parent, "resources", "#{version_string}.json").to_s
    end

    def initialize(schema_data, data, opts={})
      schema_data = ActiveSupport::HashWithIndifferentAccess.new(schema_data)
      data = ActiveSupport::HashWithIndifferentAccess.new(data)
      @options = @@default_opts.clone.merge(opts)
      @errors = []
      # I'm not a fan of this, but it's quick and dirty to get it working for now
      version_string = "draft-04"
      if @options[:version]
        version_string = @options[:version] = self.class.version_string_for(@options[:version])
        u = URI.parse("http://json-schema.org/#{@options[:version]}/schema#")
        validator = JSON::Validator.validators["#{u.scheme}://#{u.host}#{u.path}"]
        @options[:version] = validator
      end

      @validation_options = @options[:record_errors] ? {:record_errors => true} : {}
      @validation_options[:insert_defaults] = true if @options[:insert_defaults]
      @validation_options[:strict] = true if @options[:strict] == true

      @@mutex.synchronize { @base_schema = initialize_schema(schema_data) }
      @data = initialize_data(data)
      @@mutex.synchronize { build_schemas(@base_schema) }

      # validate the schema, if requested
      if @options[:validate_schema]
        begin
          if @base_schema.schema["$schema"]
            version_string = @options[:version] = self.class.version_string_for(@base_schema.schema["$schema"])
          end
          # Don't clear the cache during metaschema validation!
          meta_validator = JSON::Validator.new(self.class.metaschema_for(version_string), @base_schema.schema, {:clear_cache => false})
          meta_validator.validate
        rescue JSON::Schema::ValidationError, JSON::Schema::SchemaError
          raise $!
        end
      end

      # If the :fragment option is set, try and validate against the fragment
      if opts[:fragment]
        @base_schema = schema_from_fragment(@base_schema, opts[:fragment])
      end
    end

    def schema_from_fragment(base_schema, fragment)
      fragments = fragment.split("/")

      # ensure the first element was a hash, per the fragment spec
      if fragments.shift != "#"
        raise JSON::Schema::SchemaError.new("Invalid fragment syntax in :fragment option")
      end

      fragments.each do |f|
        if base_schema.is_a?(JSON::Schema) #test if fragment is a JSON:Schema instance
          if !base_schema.schema.has_key?(f)
            raise JSON::Schema::SchemaError.new("Invalid fragment resolution for :fragment option")
          end
        base_schema = base_schema.schema[f]
        elsif base_schema.is_a?(Hash)
          if !base_schema.has_key?(f)
            raise JSON::Schema::SchemaError.new("Invalid fragment resolution for :fragment option")
          end
        base_schema = initialize_schema(base_schema[f]) #need to return a Schema instance for validation to work
        elsif base_schema.is_a?(Array)
          if base_schema[f.to_i].nil?
            raise JSON::Schema::SchemaError.new("Invalid fragment resolution for :fragment option")
          end
        base_schema = initialize_schema(base_schema[f.to_i])
        else
          raise JSON::Schema::SchemaError.new("Invalid schema encountered when resolving :fragment option")
        end
      end
      if @options[:list] #check if the schema is validating a list
        base_schema.schema = schema_to_list(base_schema.schema)
      end
      base_schema
    end

    # Run a simple true/false validation of data against a schema
    def validate()
      begin
        @base_schema.validate(@data,[],self,@validation_options)
        if @validation_options[:clear_cache] == true
          Validator.clear_cache
        end
        if @options[:errors_as_objects]
          return @errors.map{|e| e.to_hash}
        else
          return @errors.map{|e| e.to_string}
        end
      rescue JSON::Schema::ValidationError
        if @validation_options[:clear_cache] == true
          Validator.clear_cache
        end
        raise $!
      end
    end


    def load_ref_schema(parent_schema,ref)
      uri = URI.parse(ref)
      if uri.relative?
        uri = parent_schema.uri.clone

        # Check for absolute path
        path = ref.split("#")[0]

        # This is a self reference and thus the schema does not need to be re-loaded
        if path.nil? || path == ''
          return
        end

        if path && path[0,1] == '/'
          uri.path = Pathname.new(path).cleanpath.to_s
        else
          uri = parent_schema.uri.merge(path)
        end
        uri.fragment = ''
      end

      if Validator.schemas[uri.to_s].nil?
        schema = JSON::Schema.new(JSON::Validator.parse(open(uri.to_s).read), uri, @options[:version])
        Validator.add_schema(schema)
        build_schemas(schema)
      end
    end


    # Build all schemas with IDs, mapping out the namespace
    def build_schemas(parent_schema)
      # Build ref schemas if they exist
      if parent_schema.schema["$ref"]
        load_ref_schema(parent_schema, parent_schema.schema["$ref"])
      end
      if parent_schema.schema["extends"]
        if parent_schema.schema["extends"].is_a?(String)
          load_ref_schema(parent_schema, parent_schema.schema["extends"])
        elsif parent_schema.schema["extends"].is_a?(Array)
          parent_schema.schema["extends"].each do |type|
            handle_schema(parent_schema, type)
          end
        end
      end

      # handle validations that always contain schemas
      ["allOf", "anyOf", "oneOf", "not"].each do |key|
        if parent_schema.schema.has_key?(key)
          validations = parent_schema.schema[key]
          validations = [validations] unless validations.is_a?(Array)
          validations.each {|v| handle_schema(parent_schema, v) }
        end
      end

      # Check for schemas in union types
      ["type", "disallow"].each do |key|
        if parent_schema.schema[key] && parent_schema.schema[key].is_a?(Array)
          parent_schema.schema[key].each_with_index do |type,i|
            if type.is_a?(Hash)
              handle_schema(parent_schema, type)
            end
          end
        end
      end

      # "definitions" are schemas in V4
      if parent_schema.schema["definitions"]
        parent_schema.schema["definitions"].each do |k,v|
          handle_schema(parent_schema, v)
        end
      end

      # All properties are schemas
      if parent_schema.schema["properties"]
        parent_schema.schema["properties"].each do |k,v|
          handle_schema(parent_schema, v)
        end
      end
      if parent_schema.schema["patternProperties"]
        parent_schema.schema["patternProperties"].each do |k,v|
          handle_schema(parent_schema, v)
        end
      end

      # Items are always schemas
      if parent_schema.schema["items"]
        items = parent_schema.schema["items"].clone
        single = false
        if !items.is_a?(Array)
          items = [items]
          single = true
        end
        items.each_with_index do |item,i|
          handle_schema(parent_schema, item)
        end
      end

      # Convert enum to a ArraySet
      if parent_schema.schema["enum"] && parent_schema.schema["enum"].is_a?(Array)
        parent_schema.schema["enum"] = ArraySet.new(parent_schema.schema["enum"])
      end

      # Each of these might be schemas
      ["additionalProperties", "additionalItems", "dependencies", "extends"].each do |key|
        if parent_schema.schema[key].is_a?(Hash)
          handle_schema(parent_schema, parent_schema.schema[key])
        end
      end

    end

    # Either load a reference schema or create a new schema
    def handle_schema(parent_schema, obj)
      if obj.is_a?(Hash)
        schema_uri = parent_schema.uri.clone
        schema = JSON::Schema.new(obj,schema_uri,parent_schema.validator)
        if obj['id']
          Validator.add_schema(schema)
        end
        build_schemas(schema)
      end
    end

    def validation_error(error)
      @errors.push(error)
    end

    def validation_errors
      @errors
    end


    class << self
      def validate(schema, data,opts={})
        begin
          validator = JSON::Validator.new(schema, data, opts)
          validator.validate
          return true
        rescue JSON::Schema::ValidationError, JSON::Schema::SchemaError
          return false
        end
      end

      def validate_json(schema, data, opts={})
        validate(schema, data, opts.merge(:json => true))
      end

      def validate_uri(schema, data, opts={})
        validate(schema, data, opts.merge(:uri => true))
      end

      def validate!(schema, data,opts={})
        validator = JSON::Validator.new(schema, data, opts)
        validator.validate
        return true
      end
      alias_method 'validate2', 'validate!'

      def validate_json!(schema, data, opts={})
        validate!(schema, data, opts.merge(:json => true))
      end

      def validate_uri!(schema, data, opts={})
        validate!(schema, data, opts.merge(:uri => true))
      end

      def fully_validate(schema, data, opts={})
        opts[:record_errors] = true
        validator = JSON::Validator.new(schema, data, opts)
        validator.validate
      end

      def fully_validate_schema(schema, opts={})
        data = schema
        schema = metaschema_for(version_string_for(opts[:version]))
        fully_validate(schema, data, opts)
      end

      def fully_validate_json(schema, data, opts={})
        fully_validate(schema, data, opts.merge(:json => true))
      end

      def fully_validate_uri(schema, data, opts={})
        fully_validate(schema, data, opts.merge(:uri => true))
      end

      def clear_cache
        @@schemas = {} if @@cache_schemas == false
      end

      def schemas
        @@schemas
      end

      def add_schema(schema)
        @@schemas[schema.uri.to_s] = schema if @@schemas[schema.uri.to_s].nil?
      end

      def cache_schemas=(val)
        warn "[DEPRECATION NOTICE] Schema caching is now a validation option. Schemas will still be cached if this is set to true, but this method will be removed in version >= 3. Please use the :clear_cache validation option instead."
        @@cache_schemas = val == true ? true : false
      end

      def validators
        @@validators
      end

      def default_validator
        @@default_validator
      end

      def register_validator(v)
        @@validators[v.to_s] = v
      end

      def register_default_validator(v)
        @@default_validator = v
      end

      def json_backend
        if defined?(MultiJson)
          MultiJson.respond_to?(:adapter) ? MultiJson.adapter : MultiJson.engine
        else
          @@json_backend
        end
      end

      def json_backend=(backend)
        if defined?(MultiJson)
          backend = backend == 'json' ? 'json_gem' : backend
          MultiJson.respond_to?(:use) ? MultiJson.use(backend) : MultiJson.engine = backend
        else
          backend = backend.to_s
          if @@available_json_backends.include?(backend)
            @@json_backend = backend
          else
            raise JSON::Schema::JsonParseError.new("The JSON backend '#{backend}' could not be found.")
          end
        end
      end

      def parse(s)
        if defined?(MultiJson)
          MultiJson.respond_to?(:adapter) ? MultiJson.load(s) : MultiJson.decode(s)
        else
          case @@json_backend.to_s
          when 'json'
            JSON.parse(s)
          when 'yajl'
            json = StringIO.new(s)
            parser = Yajl::Parser.new
            parser.parse(json)
          else
            raise JSON::Schema::JsonParseError.new("No supported JSON parsers found. The following parsers are suported:\n * yajl-ruby\n * json")
          end
        end
      end

      if !defined?(MultiJson)
        if begin
            Gem::Specification::find_by_name('json')
          rescue Gem::LoadError
            false
          rescue
            Gem.available?('json')
          end
          require 'json'
          @@available_json_backends << 'json'
          @@json_backend = 'json'
        end

        # Try force-loading json for rubies > 1.9.2
        begin
          require 'json'
          @@available_json_backends << 'json'
          @@json_backend = 'json'
        rescue LoadError
        end

        if begin
            Gem::Specification::find_by_name('yajl-ruby')
          rescue Gem::LoadError
            false
          rescue
            Gem.available?('yajl-ruby')
          end
          require 'yajl'
          @@available_json_backends << 'yajl'
          @@json_backend = 'yajl'
        end

        if @@json_backend == 'yajl'
          @@serializer = lambda{|o| Yajl::Encoder.encode(o) }
        else
          @@serializer = lambda{|o|
            YAML.dump(o)
          }
        end
      end
    end

    private

    if begin
        Gem::Specification::find_by_name('uuidtools')
      rescue Gem::LoadError
        false
      rescue
        Gem.available?('uuidtools')
      end
      require 'uuidtools'
      @@fake_uri_generator = lambda{|s| UUIDTools::UUID.sha1_create(UUIDTools::UUID_URL_NAMESPACE, s).to_s }
    else
      require 'json-schema/uri/uuid'
      @@fake_uri_generator = lambda{|s| JSON::Util::UUID.create_v5(s,JSON::Util::UUID::Nil).to_s }
    end

    def serialize schema
      if defined?(MultiJson)
        MultiJson.respond_to?(:dump) ? MultiJson.dump(schema) : MultiJson.encode(schema)
      else
        @@serializer.call(schema)
      end
    end

    def fake_uri schema
      @@fake_uri_generator.call(schema)
    end

    def schema_to_list(schema)
      new_schema = {"type" => "array", "items" => schema}
      if !schema["$schema"].nil?
        new_schema["$schema"] = schema["$schema"]
      end

      new_schema
    end

    def initialize_schema(schema)
      if schema.is_a?(String)
        begin
          # Build a fake URI for this
          schema_uri = URI.parse(fake_uri(schema))
          schema = JSON::Validator.parse(schema)
          if @options[:list] && @options[:fragment].nil?
            schema = schema_to_list(schema)
          end
          schema = JSON::Schema.new(schema,schema_uri,@options[:version])
          Validator.add_schema(schema)
        rescue
          # Build a uri for it
          schema_uri = URI.parse(schema)
          if schema_uri.relative?
            # Check for absolute path
            if schema[0,1] == '/'
              schema_uri = URI.parse("file://#{schema}")
            else
              schema_uri = URI.parse("file://#{Dir.pwd}/#{schema}")
            end
          end
          if Validator.schemas[schema_uri.to_s].nil?
            schema = JSON::Validator.parse(open(schema_uri.to_s).read)
            if @options[:list] && @options[:fragment].nil?
              schema = schema_to_list(schema)
            end
            schema = JSON::Schema.new(schema,schema_uri,@options[:version])
            Validator.add_schema(schema)
          else
            schema = Validator.schemas[schema_uri.to_s]
          end
        end
      elsif schema.is_a?(Hash)
        if @options[:list] && @options[:fragment].nil?
          schema = schema_to_list(schema)
        end
        schema_uri = URI.parse(fake_uri(serialize(schema)))
        schema = JSON::Schema.new(schema,schema_uri,@options[:version])
        Validator.add_schema(schema)
      else
        raise "Invalid schema - must be either a string or a hash"
      end

      schema
    end


    def initialize_data(data)
      if @options[:json]
        data = JSON::Validator.parse(data)
      elsif @options[:uri]
        json_uri = URI.parse(data)
        if json_uri.relative?
          if data[0,1] == '/'
            json_uri = URI.parse("file://#{data}")
          else
            json_uri = URI.parse("file://#{Dir.pwd}/#{data}")
          end
        end
        data = JSON::Validator.parse(open(json_uri.to_s).read)
      elsif data.is_a?(String)
        begin
          data = JSON::Validator.parse(data)
        rescue
          begin
            json_uri = URI.parse(data)
            if json_uri.relative?
              if data[0,1] == '/'
                json_uri = URI.parse("file://#{data}")
              else
                json_uri = URI.parse("file://#{Dir.pwd}/#{data}")
              end
            end
            data = JSON::Validator.parse(open(json_uri.to_s).read)
          rescue
            # Silently discard the error - the data will not change
          end
        end
      end
      JSON::Schema.add_indifferent_access(data)
      data
    end

  end
end
