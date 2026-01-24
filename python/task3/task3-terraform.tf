###########################################################################
# Template for Task 3 AWS AutoScaling Test                                #
# Do not edit the first section                                           #
# Only edit the second section to configure appropriate scaling policies  #
###########################################################################

############################
# FIRST SECTION BEGINS     #
# DO NOT EDIT THIS SECTION #
############################
locals {
  common_tags = {
    Project = "vm-scaling"
  }
  asg_tags = {
    key                 = "Project"
    value               = "vm-scaling"
    propagate_at_launch = true
  }
}

provider "aws" {
  region = "us-east-1"
}


resource "aws_security_group" "lg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "elb_asg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

######################
# FIRST SECTION ENDS #
######################

############################
# SECOND SECTION BEGINS    #
# PLEASE EDIT THIS SECTION #
############################

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Step 1:
# TODO: Add missing values below
# ================================
resource "aws_launch_template" "lt" {
  name            = "ASG_Launch_Template"
  image_id        = "ami-0e3d567ccafde16c5"
  instance_type   = "m5.large"

  monitoring {
    enabled = true
  }

  vpc_security_group_ids = [aws_security_group.elb_asg.id]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Project = "vm-scaling"
    }
  }
}

# Create an auto scaling group with appropriate parameters
# TODO: fill the missing values per the placeholders
resource "aws_autoscaling_group" "asg" {
  availability_zones        = ["us-east-1a"]
  name                      = "ASG-Web-Service"
  max_size                  = 4
  min_size                  = 1
  desired_capacity          = 1
  default_cooldown          = 50
  health_check_grace_period = 180
  health_check_type         = "EC2"
  
  launch_template {
    id      = aws_launch_template.lt.id
    version = "$Latest"
  }
  target_group_arns         = [aws_lb_target_group.asg_tg.arn]
  vpc_zone_identifier       = data.aws_subnets.default.ids
  tag {
    key = local.asg_tags.key
    value = local.asg_tags.value
    propagate_at_launch = local.asg_tags.propagate_at_launch
  }
}

# TODO: Create a Load Generator AWS instance with proper tags
resource "aws_instance" "lg" {
  ami                    = "ami-0469ff4742c562d63"
  instance_type          = "m5.large"
  vpc_security_group_ids = [aws_security_group.lg.id]
  
  tags = {
    Project = "vm-scaling"
    Name    = "Load Generator"
  }
}


# Step 2:
# TODO: Create an Application Load Balancer with appropriate listeners and target groups
# The lb_listener documentation demonstrates how to connect these resources
# Create and attach your subnet to the Application Load Balancer 
#
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group

resource "aws_lb" "asg_lb" {
  name               = "ASG-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.elb_asg.id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Project = "vm-scaling"
  }
}

resource "aws_lb_target_group" "asg_tg" {
  name     = "ASG-Target-Group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "asg_listener" {
  load_balancer_arn = aws_lb.asg_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.asg_tg.arn
  }
}


# Step 3:
# TODO: Create 2 policies: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_policy

resource "aws_autoscaling_policy" "scale_out" {
  name                   = "Scale-Out-Policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.asg.name
  policy_type            = "SimpleScaling"
}

resource "aws_autoscaling_policy" "scale_in" {
  name                   = "Scale-In-Policy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 20
  autoscaling_group_name = aws_autoscaling_group.asg.name
  policy_type            = "SimpleScaling"
}



# Step 4:
# TODO: Create 2 cloudwatch alarms: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# Don't forget to trigger the appropriate policy you created above when alarm is raised
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "Web-Service-High-CPU"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 30
  statistic           = "Average"
  threshold           = 60

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_out.arn]
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "Web-Service-Low-CPU"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 30
  statistic           = "Average"
  threshold           = 50

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_in.arn]
}


######################################
# SECOND SECTION ENDS                #
# MAKE SURE YOU COMPLETE ALL 4 STEPS #
######################################
