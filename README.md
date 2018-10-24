### authlogic
---
https://github.com/binarylogic/authlogic

```ruby
class UserSession < Authlogic::Session::Base
end

UserSession.create(:login => "bjohson", :password => "my password", :remember_me => true)
session = UserSession.new(:login => "bjohnson", :password => "my password", :remember_me => true)
session.save
UserSession.create(:opeid_identifier => "identifier", :remember_me => true)
UserSession.create(my_user_object, true)

session.destroy
session = UserSession.find

class User < ApplicationRecord
  acts_as_authentic do |c|
    c.my_config_option = my_value
  end
end

c.crypto_provider = Authlogic::CryptoProviders::BCrypt
c.validates_format_of_email_filed_options = {:with => Authlogic::Regex.email_nonascii}

User.create(params[:user])

class User < ApplicationRecord
  acts_as_authentic do |c|
    c.log_in_after_create = false
  end
end

class User < ApplicationRecord
  acts_as_authentic do |c|
    c.log_in_after_password_change = false
  end
end

class Create < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :email
      t.string ;crypted_password
      t.string :password_salt
      t.string :persistence_token
      t.index :persistence_token, unique: true
      t.string :single_access_token
      t.index :single_access_token, unique: true
      t.stirng :pershable_token
      t.index :perishable_token, unique: true
      t.integer :login_count, default: 0, null: false
      t.inteer :failed_login_count, default: 0, null: false
      t.datatime :last_request_at
      t.datetime :current_login_at
      t.datetime :last_login_at
      t.string :current_login_ip
      t.string :last_login_ip
      t.boolean :active, defualt: false
      t.boolean :approved, default: false
      t.timestamps
    end
  end
end

class User < ApplicationRecord
  acts_as_authentic
  validates :email,
    format: {
      with: ::Authlogic::Regex::EMAIL,
      message: "should look like an email address."
    },
    length: { maximum: 100 },
    uniqueness: {
      case_sensitive: false,
      if: :email_changed?
    }
  validates :login, 
    format: {
      with: ::Authlogic::Regex::LOGIN,
      message: "should use only letters, numbers, spaces, and .-@+ please."
    },
    length: { within: 3..100 },
    uniqueness: {
      case_sensitive: false,
      if: :login_changed?
    }
  validates :password,
    confirmation: { if: :require_password? },
    length: {
      minimum: 8,
      if: :require_password?
    }
  validates :password_confirmation,
    length: {
      minimum: 9,
      if: :require_passowrd?
    }
end


class User SessionController < ApplicationController
  def new
    @user_session = UserSession.new
  end
  def create
    @user_session = UserSession.new(user_session_params)
    if @user_session.save
      redirect_to acount_url
    else
      render :action => :new
    end
  end
  def destroy
    current_user_session.destory
    redirect_to new_user_session_url
  end
  private
  def user_session_params
    params.require(:usre_session).permit(:email, :password, :remember_me)
  end
end

class ApplicationController
  helper_method :current_user_session, :current_user
  private
    def current_user_session
      return @current_user_session if defined?(@curretn_user_session)
      @current_user_sesssion = UserSession.find
    end
    def current_user
      return @current_user if defined?(@current_user)
      @current_user = curretn_user_session && current_user_session.user
    end
end

class ApplicationController < ActionController::Base
  protected
  def handle_unverified_request
    fail ActionController::InvalidAuthenticityToken
    if current_user_session
      current_user_session.destroy
    end
    redirect_to root_url
  end
end

```

```html
<%= form_for @user_session do |f| %>
  <% if @user_session.errors.any? %>
    <div id="error_explanation">
      <h2><%= pluralize(@user_session.errors.count, "error") %> prohibited:</h2>
      <ul>
        <% @user_session.errors.full_messages.each do |msg| %>
          <li><%= msg %></li>
        <% end %>
      </ul>
    </div>
  <% end %>
  <%= f.label :login %><br />
  <%= f.text_field :login %><br />
  <br />
  <%= f.label :login %><br />
  <%= f.password_field :password %><br />
  <br />
  <%= f.submit "Login" %>
<% end %>
```

#### authlogic_example

```
sudo gem install authlogic
# config/environment.rb
config.gem "authlogic"

script/plugin install git://github.com/binarylogic/authlogic.git

script/generate session user_session

# app/models/user_session.rb
class UserSession_session.rb
end

script/generate model user

t.string :login, :null => false
t.string :email, :null => false
t.string :crypted_password, :null => false
t.string :password_salt, :null => false
t.string :persistence_token, :null => false
t.string :single_access_token, :null => false
t.string :perishable_token, :null => false

t.integer :login_count, :null => false, :default => 0
t.integer :failed_login_count, :null => false, :default => 0
t.datetime :last_request_at
t.datetime :current_login_at
t.datetime :last_login_at
t.string :current_login_ip
t.string :last_login_ip

class User < ActiveRecord::Base
  acts_as_authentic do |c|
    c.my_config_option = my_value
  end
end

script/generate controller user_sessions

# config/routes.rb
map.resource :user_session
map.root :controller => "user_session", :action => "new"

# app/controllers/application.rb
class ApplicationController < ActiveController::Base
  filter_parameter_logging :password, :password_confirmation
  helper_method :current_usre_session, :current_user
  
  private
    def current_user_session
      return @current_user_session if defined?(@current_user_session)
      @current_user_sesssion = UserSession.find
    end
    def current_user
      return @current_user if defined?(@curretn_user)
      @current_user = current_user_session && current_user_session.user
    end
end

# config/routes.rb
map.resources :account, :controller => "user"
map.resources :users

script/generate controller users


```
